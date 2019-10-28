/*
Copyright 2019 Gravitational, Inc.

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

	"github.com/gravitational/teleport/lib/utils"

	. "gopkg.in/check.v1"
)

type AccessRequestSuite struct {
}

var _ = Suite(&AccessRequestSuite{})
var _ = fmt.Printf

func (s *AccessRequestSuite) SetUpSuite(c *C) {
	utils.InitLoggerForTests()
}

// TestRequestMarshaling verifies that marshaling/unmarshaling access requests
// works as expected (failures likely indicate a problem with json schema).
func (s *AccessRequestSuite) TestRequestMarshaling(c *C) {
	req1, err := NewAccessRequest("some-user", "role-1", "role-2")
	c.Assert(err, IsNil)

	marshaled, err := GetAccessRequestMarshaler().MarshalAccessRequest(req1)
	c.Assert(err, IsNil)

	req2, err := GetAccessRequestMarshaler().UnmarshalAccessRequest(marshaled)
	c.Assert(err, IsNil)

	if !req1.Equals(req2) {
		c.Errorf("unexpected inequality %+v <---> %+v", req1, req2)
	}
}

// TestRequestFiltering verifies expected matching behavior for AccessRequestFilter.
func (s *AccessRequestSuite) TestRequestFiltering(c *C) {
	reqA, err := NewAccessRequest("alice", "role-a")
	c.Assert(err, IsNil)

	reqB, err := NewAccessRequest("bob", "role-b")
	c.Assert(err, IsNil)

	testCases := []struct {
		user   string
		id     string
		matchA bool
		matchB bool
	}{
		{"", "", true, true},
		{"alice", "", true, false},
		{"", reqA.GetName(), true, false},
		{"bob", reqA.GetName(), false, false},
		{"carol", "", false, false},
	}
	for _, tc := range testCases {
		m := AccessRequestFilter{
			User: tc.user,
			ID:   tc.id,
		}
		if m.Match(reqA) != tc.matchA {
			c.Errorf("bad filter behavior (a) %+v", tc)
		}
		if m.Match(reqB) != tc.matchB {
			c.Errorf("bad filter behavior (b) %+v", tc)
		}
	}
}
