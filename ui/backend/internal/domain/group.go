package domain

// Group is the application's view of a groupOfNames entry.
type Group struct {
	DN          string   `json:"dn"`
	CN          string   `json:"cn"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members"`
}

// GroupInput is the payload for creating or updating a group's own
// attributes. Membership is managed separately via AddMember/RemoveMember so
// large groups don't require re-sending the whole member list.
type GroupInput struct {
	CN          string `json:"cn"`
	Description string `json:"description,omitempty"`
}
