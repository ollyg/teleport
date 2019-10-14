/*
Copyright 2016 Gravitational, Inc.

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

package local

import (
	"bytes"
	"context"

	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"

	"github.com/gravitational/trace"
)

// DynamicAccessService manages dynamic RBAC
type DynamicAccessService struct {
	backend.Backend
}

// NewDynamicAccessService returns new dynamic access service instance
func NewDynamicAccessService(backend backend.Backend) *AccessService {
	return &AccessService{Backend: backend}
}

func (s *AccessService) CreateRoleRequest(req services.RoleRequest) error {
	if err := req.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	item, err := itemFromRoleRequest(req)
	if err != nil {
		return trace.Wrap(err)
	}
	if _, err := s.Create(context.TODO(), item); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (s *AccessService) SetRoleRequestState(name string, state services.RequestState) error {
	item, err := s.Get(context.TODO(), roleRequestKey(name))
	if err != nil {
		if trace.IsNotFound(err) {
			return trace.NotFound("cannot set state of role request %q (not found)", name)
		}
		return trace.Wrap(err)
	}
	req, err := itemToRoleRequest(*item)
	if err != nil {
		return trace.Wrap(err)
	}
	if err := req.SetState(state); err != nil {
		return trace.Wrap(err)
	}
	newItem, err := itemFromRoleRequest(req)
	if err != nil {
		return trace.Wrap(err)
	}
	if _, err := s.CompareAndSwap(context.TODO(), *item, newItem); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (s *AccessService) GetRoleRequest(name string) (services.RoleRequest, error) {
	item, err := s.Get(context.TODO(), roleRequestKey(name))
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.NotFound("role request %q not found", name)
		}
		return nil, trace.Wrap(err)
	}
	req, err := itemToRoleRequest(*item)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return req, nil
}

func (s *AccessService) GetRoleRequests() ([]services.RoleRequest, error) {
	result, err := s.GetRange(context.TODO(), backend.Key(roleRequestsPrefix), backend.RangeEnd(backend.Key(roleRequestsPrefix)), backend.NoLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var requests []services.RoleRequest
	for _, item := range result.Items {
		if !bytes.HasSuffix(item.Key, []byte(paramsPrefix)) {
			continue
		}
		req, err := itemToRoleRequest(item)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		requests = append(requests, req)
	}
	return requests, nil
}

func (s *AccessService) DeleteRoleRequest(name string) error {
	err := s.Delete(context.TODO(), roleRequestKey(name))
	if err != nil {
		if trace.IsNotFound(err) {
			return trace.NotFound("cannot delete role request %q (not found)", name)
		}
		return trace.Wrap(err)
	}
	return nil
}

func itemFromRoleRequest(req services.RoleRequest) (backend.Item, error) {
	value, err := services.GetRoleRequestMarshaler().MarshalRoleRequest(req)
	if err != nil {
		return backend.Item{}, trace.Wrap(err)
	}
	return backend.Item{
		Key:     roleRequestKey(req.GetName()),
		Value:   value,
		Expires: req.Expiry(),
		ID:      req.GetResourceID(),
	}, nil
}

func itemToRoleRequest(item backend.Item) (services.RoleRequest, error) {
	req, err := services.GetRoleRequestMarshaler().UnmarshalRoleRequest(
		item.Value,
		services.WithResourceID(item.ID),
		services.WithExpires(item.Expires),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return req, nil
}

func roleRequestKey(name string) []byte {
	return backend.Key(roleRequestsPrefix, name, paramsPrefix)
}

const (
	roleRequestsPrefix = "role_requests"
)