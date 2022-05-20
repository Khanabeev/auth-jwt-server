package user

type Storage interface {
	FindUserByEmail(email string) (*User, error)
	CreateNewUser(user *User) (*User, error)
}
