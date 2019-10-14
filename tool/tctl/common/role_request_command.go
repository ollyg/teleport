/*
Copyright 2015-2017 Gravitational, Inc.

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

package common

import (
	//"encoding/json"
	"fmt"
	"os"
	"strings"
	//"time"

	"github.com/gravitational/kingpin"
	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/asciitable"
	"github.com/gravitational/teleport/lib/auth"
	//"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/services"
	//"github.com/gravitational/teleport/lib/web"
	"github.com/gravitational/trace"
)

// RoleRequestCommand implements `tctl users` set of commands
// It implements CLICommand interface
type RoleRequestCommand struct {
	config *service.Config
	reqIDs []string

	user  string
	roles []string
	// format is the output format, e.g. text or json
	format string

	requestList    *kingpin.CmdClause
	requestApprove *kingpin.CmdClause
	requestDeny    *kingpin.CmdClause
	requestCreate  *kingpin.CmdClause
}

// Initialize allows RoleRequestCommand to plug itself into the CLI parser
func (c *RoleRequestCommand) Initialize(app *kingpin.Application, config *service.Config) {
	c.config = config
	requests := app.Command("role-request", "Manage role requests")

	c.requestList = requests.Command("list", "Show active role requests")
	c.requestList.Flag("format", "Output format, 'text' or 'json'").Hidden().Default(teleport.Text).StringVar(&c.format)

	c.requestApprove = requests.Command("approve", "Approve pending role request")
	c.requestApprove.Arg("request-id", "ID of target request(s)").Required().StringsVar(&c.reqIDs)

	c.requestDeny = requests.Command("deny", "Deny pending role request")
	c.requestDeny.Arg("request-id", "ID of target request(s)").Required().StringsVar(&c.reqIDs)

	c.requestCreate = requests.Command("create", "Create pending role request")
	c.requestCreate.Arg("username", "Name of target user").Required().StringVar(&c.user)
	c.requestCreate.Arg("roles", "Roles to be requested").Required().StringsVar(&c.roles)
}

// TryRun takes the CLI command as an argument (like "role-request list") and executes it.
func (c *RoleRequestCommand) TryRun(cmd string, client auth.ClientI) (match bool, err error) {
	switch cmd {
	case c.requestList.FullCommand():
		err = c.List(client)
	case c.requestApprove.FullCommand():
		err = c.Approve(client)
	case c.requestDeny.FullCommand():
		err = c.Deny(client)
	case c.requestCreate.FullCommand():
		err = c.Create(client)
	default:
		return false, nil
	}
	return true, trace.Wrap(err)
}

func (c *RoleRequestCommand) List(client auth.ClientI) error {
	reqs, err := client.GetRoleRequests()
	if err != nil {
		return trace.Wrap(err)
	}
	if err := c.PrintRoleRequests(client, reqs, c.format); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (c *RoleRequestCommand) Approve(client auth.ClientI) error {
	for _, reqID := range c.reqIDs {
		if err := client.SetRoleRequestState(reqID, services.RequestState_APPROVED); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (c *RoleRequestCommand) Deny(client auth.ClientI) error {
	for _, reqID := range c.reqIDs {
		if err := client.SetRoleRequestState(reqID, services.RequestState_DENIED); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (c *RoleRequestCommand) Create(client auth.ClientI) error {
	req, err := services.NewRoleRequest(c.user, c.roles...)
	if err != nil {
		return trace.Wrap(err)
	}
	if err := client.CreateRoleRequest(req); err != nil {
		return trace.Wrap(err)
	}
	fmt.Printf("%s\n", req.GetName())
	return nil
}

// PrintRoleRequests prints role requests
func (c *RoleRequestCommand) PrintRoleRequests(client auth.ClientI, reqs []services.RoleRequest, format string) error {
	if format == teleport.Text {
		table := asciitable.MakeTable([]string{"ID", "user", "role(s)", "state"})
		for _, req := range reqs {
			table.AddRow([]string{
				req.GetName(),
				req.GetUser(),
				strings.Join(req.GetRoles(), ","),
				req.GetState().String(),
			})
		}
		_, err := table.AsBuffer().WriteTo(os.Stdout)
		return trace.Wrap(err)
	} else {
		panic("NOT IMPLEMENTED")
	}
}
