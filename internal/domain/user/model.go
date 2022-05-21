package user

type User struct {
	ID        int    `json:"id,omitempty"`
	Email     string `json:"email"`
	Password  string `json:"-"`
	Status    int    `json:"status,omitempty"`
	Role      string `json:"role,omitempty"`
	CreatedAt string `json:"created_at,omitempty" db:"created_at"`
	UpdatedAt string `json:"updated_at,omitempty" db:"updated_at"`
	DeletedAt string `json:"deleted_at,omitempty" db:"deleted_at"`
}
