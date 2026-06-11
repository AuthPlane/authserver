package configast

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
)

// Parse reads internal/config/{config,loader,validate}.go under
// configDir and returns a flat Model. validate.go is optional —
// when absent, RequiredWhen on every Field is "".
//
// Parse never returns a partial Model: if any source file fails to
// parse, the caller gets a non-nil error and a nil Model.
func Parse(configDir string) (*Model, error) {
	fset := token.NewFileSet()

	configFile, err := parser.ParseFile(fset, filepath.Join(configDir, "config.go"), nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse config.go: %w", err)
	}
	loaderFile, err := parser.ParseFile(fset, filepath.Join(configDir, "loader.go"), nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse loader.go: %w", err)
	}
	var validateFile *ast.File
	validatePath := filepath.Join(configDir, "validate.go")
	if vf, err := parser.ParseFile(fset, validatePath, nil, parser.ParseComments); err == nil {
		validateFile = vf
	}
	// validate.go absence is non-fatal.

	structs, sections := collectStructs(configFile)
	defaults := collectDefaults(loaderFile, structs)
	envBindings := collectEnvBindings(loaderFile, structs)
	requireds := map[string]string{}
	if validateFile != nil {
		requireds = collectRequiredWhen(validateFile)
	}

	fields := flattenFields(structs, "Config", "", defaults, envBindings, requireds)

	// Build the EnvVars slice in source order (the walker
	// already returns it that way) but with YAMLPath resolved.
	envVars := make([]EnvVar, 0, len(envBindings))
	for _, b := range envBindings {
		envVars = append(envVars, EnvVar{
			Name:     b.name,
			YAMLPath: b.yamlPath,
			Helper:   b.helper,
			Pos:      b.pos,
		})
	}

	return &Model{
		Fset:             fset,
		Fields:           fields,
		EnvVars:          envVars,
		TopLevelSections: sections,
	}, nil
}

// structInfo captures everything the walker needs to know about a
// struct declaration in config.go.
type structInfo struct {
	name   string // Go type name, e.g. "ServerConfig"
	doc    string // leading doc-comment, cleaned
	fields []sfield
	pos    token.Pos
}

// sfield is one field on a struct.
type sfield struct {
	goName   string   // "Issuer"
	yamlName string   // "issuer" or "" when no yaml tag
	yamlOpts []string // "omitempty" etc — not used today but cheap to keep
	goType   string   // "string", "time.Duration", "[]string", "SQLiteConfig"
	humanT   string   // normalised type for docs
	comment  string   // leading or trailing comment, cleaned
	pos      token.Pos
}

// collectStructs walks the config.go AST and returns a map keyed by
// Go type name. It also returns the ordered list of top-level
// Config-fields with their YAML keys, so the configuration.md
// generator can render H2 sections in declaration order.
func collectStructs(f *ast.File) (map[string]*structInfo, []Section) {
	out := map[string]*structInfo{}

	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			info := &structInfo{
				name: ts.Name.Name,
				pos:  ts.Pos(),
				doc:  cleanComment(gd.Doc),
			}
			for _, field := range st.Fields.List {
				yamlName, opts := extractYAMLTag(field.Tag)
				goType := renderType(field.Type)
				humanT := normaliseType(goType)
				comment := pickFieldComment(field)
				// One *ast.Field can declare multiple names
				// (rare in this codebase) — fan out.
				for _, n := range field.Names {
					info.fields = append(info.fields, sfield{
						goName:   n.Name,
						yamlName: yamlName,
						yamlOpts: opts,
						goType:   goType,
						humanT:   humanT,
						comment:  comment,
						pos:      n.Pos(),
					})
				}
			}
			out[info.name] = info
		}
	}

	// Resolve top-level sections from Config.
	sections := []Section{}
	if root, ok := out["Config"]; ok {
		for _, fld := range root.fields {
			if fld.yamlName == "" {
				continue
			}
			ty := strings.TrimPrefix(fld.goType, "[]")
			child := out[ty]
			doc := ""
			if child != nil {
				doc = child.doc
			}
			sections = append(sections, Section{
				YAMLKey:    fld.yamlName,
				GoTypeName: ty,
				Comment:    doc,
				Pos:        fld.pos,
			})
		}
	}

	return out, sections
}

// flattenFields walks the struct graph from the root and emits one
// Field per leaf YAML key in dotted-path order.
func flattenFields(
	structs map[string]*structInfo,
	rootTypeName, pathPrefix string,
	defaults map[string]string,
	envBindings []envBinding,
	requireds map[string]string,
) []Field {
	// Build a YAML-path -> env-var lookup for fast cross-reference.
	envByPath := map[string]string{}
	for _, b := range envBindings {
		// Last writer wins; in practice each YAML path has a
		// single binding (or none).
		envByPath[b.yamlPath] = b.name
	}

	root := structs[rootTypeName]
	if root == nil {
		return nil
	}
	var out []Field
	visit(structs, root, pathPrefix, "", defaults, envByPath, requireds, &out)
	return out
}

// visit recurses through nested struct fields, emitting one Field
// per leaf yaml-tagged field.
func visit(
	structs map[string]*structInfo,
	cur *structInfo,
	prefix, section string,
	defaults map[string]string,
	envByPath, requireds map[string]string,
	out *[]Field,
) {
	for _, f := range cur.fields {
		if f.yamlName == "" {
			continue
		}
		path := f.yamlName
		if prefix != "" {
			path = prefix + "." + f.yamlName
		}
		// Determine the section: top-level keys carry their own
		// name; nested fields inherit the section passed in.
		thisSection := section
		if thisSection == "" {
			thisSection = f.yamlName
		}

		// Recurse into nested struct types (but not into slice
		// elements — `[]ResourceConfigUnified` is a leaf for
		// the docs). The struct must live in the same package
		// for recursion; the walker treats unknown types as
		// scalar leaves.
		bareTy := strings.TrimPrefix(f.goType, "[]")
		isSliceOfStruct := strings.HasPrefix(f.goType, "[]")
		if !isSliceOfStruct {
			if child, ok := structs[bareTy]; ok {
				visit(structs, child, path, thisSection, defaults, envByPath, requireds, out)
				continue
			}
		}

		*out = append(*out, Field{
			YAMLPath:     path,
			Section:      thisSection,
			GoType:       f.goType,
			HumanType:    f.humanT,
			Comment:      f.comment,
			Default:      defaults[path],
			EnvVar:       envByPath[path],
			RequiredWhen: requireds[path],
			Pos:          f.pos,
		})
	}
}
