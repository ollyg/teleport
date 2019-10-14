/*
Copyright 2016-2019 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package services

import (
	"fmt"
	"time"

	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"

	"github.com/jonboulle/clockwork"
	"github.com/pborman/uuid"
)

// DynamicAccess is a service which manages dynamic RBAC.
type DynamicAccess interface {
	// CreateRoleRequest stores a new role request.
	CreateRoleRequest(RoleRequest) error
	// SetRoleRequestState updates the state of an existing role request.
	SetRoleRequestState(reqID string, state RequestState) error
	// GetRoleRequest gets a role request by name (uuid).
	GetRoleRequest(string) (RoleRequest, error)
	// GetRoleRequests gets all currently active role requests.
	GetRoleRequests() ([]RoleRequest, error)
	// DeleteRoleRequest deletes a role request.
	DeleteRoleRequest(string) error
}

// RoleRequest is a request for temporarily granted roles
type RoleRequest interface {
	Resource
	// GetUser gets the name of the requesting user
	GetUser() string
	// GetRoles gets the roles being requested by the user
	GetRoles() []string
	// GetState gets the current state of the request
	GetState() RequestState
	// SetApproved sets the approval state of the request
	SetState(RequestState) error

	CheckAndSetDefaults() error
}

func (s RequestState) IsPending() bool {
	return s == RequestState_PENDING
}

func (s RequestState) IsApproved() bool {
	return s == RequestState_APPROVED
}

func (s RequestState) IsDenied() bool {
	return s == RequestState_DENIED
}

// NewRoleRequest assembled a RoleRequest resource.
func NewRoleRequest(user string, roles ...string) (RoleRequest, error) {
	req := RoleRequestV1{
		Kind:    KindRoleRequest,
		Version: V3,
		Metadata: Metadata{
			Name: uuid.New(),
			// TODO: add expiry
		},
		Spec: RoleRequestSpecV1{
			User:  user,
			Roles: roles,
			State: RequestState_PENDING,
		},
	}
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &req, nil
}

func (r *RoleRequestV1) GetUser() string {
	return r.Spec.User
}

func (r *RoleRequestV1) GetRoles() []string {
	return r.Spec.Roles
}

func (r *RoleRequestV1) GetState() RequestState {
	return r.Spec.State
}

func (r *RoleRequestV1) SetState(state RequestState) error {
	if r.Spec.State.IsDenied() {
		if state.IsDenied() {
			return nil
		}
		return trace.BadParameter("cannot set request-state %q (already denied)", state.String())
	}
	r.Spec.State = state
	return nil
}

func (r *RoleRequestV1) CheckAndSetDefaults() error {
	if err := r.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if err := r.Check(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (r *RoleRequestV1) Check() error {
	if r.Kind == "" {
		return trace.BadParameter("role request kind not set")
	}
	if r.Version == "" {
		return trace.BadParameter("role request version not set")
	}
	if r.GetName() == "" {
		return trace.BadParameter("role request name not set")
	}
	if r.GetUser() == "" {
		return trace.BadParameter("role request user name not set")
	}
	if len(r.GetRoles()) < 1 {
		return trace.BadParameter("role request does not specify any roles")
	}
	return nil
}

// --------------------------------------------------------------------

type RoleRequestMarshaler interface {
	MarshalRoleRequest(req RoleRequest, opts ...MarshalOption) ([]byte, error)
	UnmarshalRoleRequest(bytes []byte, opts ...MarshalOption) (RoleRequest, error)
}

type roleRequestMarshaler struct{}

func (r *roleRequestMarshaler) MarshalRoleRequest(req RoleRequest, opts ...MarshalOption) ([]byte, error) {
	cfg, err := collectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch r := req.(type) {
	case *RoleRequestV1:
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			cp := *r
			cp.SetResourceID(0)
			r = &cp
		}
		return utils.FastMarshal(r)
	default:
		return nil, trace.BadParameter("unrecognized role request type: %T", req)
	}
}

func (r *roleRequestMarshaler) UnmarshalRoleRequest(data []byte, opts ...MarshalOption) (RoleRequest, error) {
	cfg, err := collectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var req RoleRequestV1
	if cfg.SkipValidation {
		if err := utils.FastUnmarshal(data, &req); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if err := utils.UnmarshalWithSchema(GetRoleRequestSchema(), &req, data); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	if cfg.ID != 0 {
		req.SetResourceID(cfg.ID)
	}
	if !cfg.Expires.IsZero() {
		req.SetExpiry(cfg.Expires)
	}
	return &req, nil
}

var roleRequestMarshalerInstance RoleRequestMarshaler = &roleRequestMarshaler{}

func GetRoleRequestMarshaler() RoleRequestMarshaler {
	marshalerMutex.Lock()
	defer marshalerMutex.Unlock()
	return roleRequestMarshalerInstance
}

const RoleRequestSpecSchema = `{
	"type": "object",
	"additionalProperties": false,
	"properties": {
		"user": { "type": "string" },
		"roles": {
			"type": "array",
			"items": { "type": "string" }
		},
		"state": { "type": "integer" }
	}
}`

func GetRoleRequestSchema() string {
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, RoleRequestSpecSchema, DefaultDefinitions)
}

// --------------------------------------------------------------------

func (r *RoleRequestV1) GetKind() string {
	return r.Kind
}

func (r *RoleRequestV1) GetSubKind() string {
	return r.SubKind
}

func (r *RoleRequestV1) SetSubKind(subKind string) {
	r.SubKind = subKind
}

func (r *RoleRequestV1) GetVersion() string {
	return r.Version
}

func (r *RoleRequestV1) GetName() string {
	return r.Metadata.Name
}

func (r *RoleRequestV1) SetName(name string) {
	r.Metadata.Name = name
}

func (r *RoleRequestV1) Expiry() time.Time {
	return r.Metadata.Expiry()
}

func (r *RoleRequestV1) SetExpiry(expiry time.Time) {
	r.Metadata.SetExpiry(expiry)
}

func (r *RoleRequestV1) SetTTL(clock clockwork.Clock, ttl time.Duration) {
	r.Metadata.SetTTL(clock, ttl)
}

func (r *RoleRequestV1) GetMetadata() Metadata {
	return r.Metadata
}

func (r *RoleRequestV1) GetResourceID() int64 {
	return r.Metadata.GetID()
}

func (r *RoleRequestV1) SetResourceID(id int64) {
	r.Metadata.SetID(id)
}

func (r *RoleRequestV1) String() string {
	return fmt.Sprintf("RoleRequest(user=%v,roles=%+v)", r.Spec.User, r.Spec.Roles)
}
