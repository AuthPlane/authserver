package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/input"
)

// userCmd is the parent for user management subcommands.
var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage users",
	Args:  cobra.NoArgs, // unknown subcommand → loud error (see admin.go)
	RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
}

// --- user create ---

var userCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new user",
	RunE: func(cmd *cobra.Command, args []string) error {
		bindEnv(cmd, "email", "AUTHSERVER_USER_EMAIL")
		bindEnv(cmd, "password", "AUTHSERVER_USER_PASSWORD")
		bindEnv(cmd, "name", "AUTHSERVER_USER_NAME")
		bindEnv(cmd, "role", "AUTHSERVER_USER_ROLE")

		email, _ := cmd.Flags().GetString("email")
		password, _ := cmd.Flags().GetString("password")
		name, _ := cmd.Flags().GetString("name")
		role, _ := cmd.Flags().GetString("role")

		if email == "" || password == "" {
			return fmt.Errorf("--email and --password are required")
		}

		var userRole user.Role
		switch role {
		case "admin":
			userRole = user.RoleAdmin
		case "user":
			userRole = user.RoleUser
		default:
			return fmt.Errorf("invalid role %q: must be admin or user", role)
		}

		env, cleanup, err := openAdminCLI()
		if err != nil {
			return err
		}
		defer cleanup()

		u, err := env.adminSvc.CreateUser(context.Background(), input.CreateUserRequest{
			Email:    email,
			Name:     name,
			Password: password,
			Role:     userRole,
		})
		if err != nil {
			return fmt.Errorf("create user: %w", err)
		}

		fmt.Printf("user created: id=%s email=%s role=%s\n", u.ID, u.Email, u.Role)
		return nil
	},
}

// --- user update ---

var userUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update an existing user",
	RunE: func(cmd *cobra.Command, args []string) error {
		bindEnv(cmd, "id", "AUTHSERVER_USER_ID")
		id, _ := cmd.Flags().GetString("id")
		if id == "" {
			return fmt.Errorf("--id is required")
		}

		env, cleanup, err := openAdminCLI()
		if err != nil {
			return err
		}
		defer cleanup()

		var req input.UpdateUserRequest
		if cmd.Flags().Changed("email") {
			v, _ := cmd.Flags().GetString("email")
			req.Email = &v
		}
		if cmd.Flags().Changed("name") {
			v, _ := cmd.Flags().GetString("name")
			req.Name = &v
		}

		updated, err := env.adminSvc.UpdateUser(context.Background(), id, req)
		if err != nil {
			return fmt.Errorf("update user: %w", err)
		}

		fmt.Printf("user updated: id=%s email=%s name=%s\n", updated.ID, updated.Email, updated.Name)
		return nil
	},
}

// --- user delete ---

var userDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a user",
	RunE: func(cmd *cobra.Command, args []string) error {
		bindEnv(cmd, "id", "AUTHSERVER_USER_ID")
		id, _ := cmd.Flags().GetString("id")
		force, _ := cmd.Flags().GetBool("force")

		if id == "" {
			return fmt.Errorf("--id is required")
		}

		env, cleanup, err := openAdminCLI()
		if err != nil {
			return err
		}
		defer cleanup()

		if err := env.adminSvc.DeleteUser(context.Background(), id, force); err != nil {
			return fmt.Errorf("delete user: %w", err)
		}

		fmt.Printf("user deleted: id=%s\n", id)
		return nil
	},
}

// --- user force-logout ---

var userForceLogoutCmd = &cobra.Command{
	Use:   "force-logout",
	Short: "Revoke all tokens for a user",
	RunE: func(cmd *cobra.Command, args []string) error {
		bindEnv(cmd, "id", "AUTHSERVER_USER_ID")
		id, _ := cmd.Flags().GetString("id")
		if id == "" {
			return fmt.Errorf("--id is required")
		}

		env, cleanup, err := openAdminCLI()
		if err != nil {
			return err
		}
		defer cleanup()

		count, err := env.adminSvc.ForceLogoutUser(context.Background(), id)
		if err != nil {
			return fmt.Errorf("force logout: %w", err)
		}

		fmt.Printf("user %s force-logged out: %d token families revoked\n", id, count)
		return nil
	},
}

// --- user list ---

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users",
	RunE: func(cmd *cobra.Command, args []string) error {
		env, cleanup, err := openAdminCLI()
		if err != nil {
			return err
		}
		defer cleanup()

		users, err := env.adminSvc.ListUsers(cmd.Context())
		if err != nil {
			return fmt.Errorf("list users: %w", err)
		}

		for _, u := range users {
			fmt.Printf("id=%s email=%s role=%s status=%s\n", u.ID, u.Email, u.Role, u.Status)
		}
		if len(users) == 0 {
			fmt.Println("no users found")
		}
		return nil
	},
}

func init() {
	// user create flags.
	userCreateCmd.Flags().String("email", "", "User email (required)")
	userCreateCmd.Flags().String("password", "", "User password (required)")
	userCreateCmd.Flags().String("name", "", "User display name")
	userCreateCmd.Flags().String("role", "user", "User role: admin or user")

	// user update flags (stubs for ).
	userUpdateCmd.Flags().String("id", "", "User ID (required)")
	userUpdateCmd.Flags().String("email", "", "New email")
	userUpdateCmd.Flags().String("name", "", "New display name")

	// user delete flags (stubs for ).
	userDeleteCmd.Flags().String("id", "", "User ID (required)")
	userDeleteCmd.Flags().Bool("force", false, "Force delete even with active tokens")

	// user force-logout flags (stubs for ).
	userForceLogoutCmd.Flags().String("id", "", "User ID (required)")

	userCmd.AddCommand(userCreateCmd)
	userCmd.AddCommand(userUpdateCmd)
	userCmd.AddCommand(userDeleteCmd)
	userCmd.AddCommand(userForceLogoutCmd)
	userCmd.AddCommand(userListCmd)
}
