package auth

import (
	"strings"
)

type RolePermissions struct {
	rolePermissions map[string][]string
}

func (p RolePermissions) IsAuthorizedFor(role string, routeName string) bool {
	perms := GetRolePermissions().rolePermissions[role]
	for _, r := range perms {
		if r == strings.TrimSpace(routeName) {
			return true
		}
	}
	return false
}

func GetRolePermissions() RolePermissions {
	return RolePermissions{map[string][]string{
		"admin": {},
		"user": {
			"GetUserProfile",
			"CreateGoal",
			"GetGoal",
			"GetAllGoals",
			"UpdateGoal",
			"DeleteGoal",
			"CreateTask",
			"GetTask",
			"GetAllTasks",
			"GetAllTasksByGoal",
			"GetTaskById",
			"UpdateTask",
			"DeleteTask",
		},
	}}
}
