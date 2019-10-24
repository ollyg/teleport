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
	"time"

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

// AccessRequestCommand implements `tctl users` set of commands
// It implements CLICommand interface
type AccessRequestCommand struct {
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
	requestDelete  *kingpin.CmdClause
}

// Initialize allows AccessRequestCommand to plug itself into the CLI parser
func (c *AccessRequestCommand) Initialize(app *kingpin.Application, config *service.Config) {
	c.config = config
	requests := app.Command("request", "Manage access requests")

	c.requestList = requests.Command("ls", "Show active access requests")
	c.requestList.Flag("format", "Output format, 'text' or 'json'").Hidden().Default(teleport.Text).StringVar(&c.format)

	c.requestApprove = requests.Command("approve", "Approve pending access request")
	c.requestApprove.Arg("request-id", "ID of target request(s)").Required().StringsVar(&c.reqIDs)

	c.requestDeny = requests.Command("deny", "Deny pending access request")
	c.requestDeny.Arg("request-id", "ID of target request(s)").Required().StringsVar(&c.reqIDs)

	c.requestCreate = requests.Command("create", "Create pending access request")
	c.requestCreate.Arg("username", "Name of target user").Required().StringVar(&c.user)
	c.requestCreate.Arg("roles", "Roles to be requested").Required().StringsVar(&c.roles)

	c.requestDelete = requests.Command("del", "Delete an access request")
	c.requestDelete.Arg("request-id", "ID of target request(s)").Required().StringsVar(&c.reqIDs)
}

// TryRun takes the CLI command as an argument (like "access-request list") and executes it.
func (c *AccessRequestCommand) TryRun(cmd string, client auth.ClientI) (match bool, err error) {
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

func (c *AccessRequestCommand) List(client auth.ClientI) error {
	reqs, err := client.GetAccessRequests(services.AccessRequestFilter{})
	if err != nil {
		return trace.Wrap(err)
	}
	if err := c.PrintAccessRequests(client, reqs, c.format); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (c *AccessRequestCommand) Approve(client auth.ClientI) error {
	for _, reqID := range c.reqIDs {
		if err := client.SetAccessRequestState(reqID, services.RequestState_APPROVED); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (c *AccessRequestCommand) Deny(client auth.ClientI) error {
	for _, reqID := range c.reqIDs {
		if err := client.SetAccessRequestState(reqID, services.RequestState_DENIED); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (c *AccessRequestCommand) Create(client auth.ClientI) error {
	req, err := services.NewAccessRequest(c.user, c.roles...)
	if err != nil {
		return trace.Wrap(err)
	}
	if err := client.CreateAccessRequest(req); err != nil {
		return trace.Wrap(err)
	}
	fmt.Printf("%s\n", req.GetName())
	return nil
}

func (c *AccessRequestCommand) Delete(client auth.ClientI) error {
	for _, reqID := range c.reqIDs {
		if err := client.DeleteAccessRequest(reqID); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// PrintAccessRequests prints access requests
func (c *AccessRequestCommand) PrintAccessRequests(client auth.ClientI, reqs []services.AccessRequest, format string) error {
	if format == teleport.Text {
		table := asciitable.MakeTable([]string{"ID", "user", "role(s)", "state", "ttl"})
		now := time.Now()
		for _, req := range reqs {
			if now.After(req.Expiry()) {
				continue
			}
			ttl := req.Expiry().Sub(now).Round(time.Second)
			table.AddRow([]string{
				req.GetName(),
				req.GetUser(),
				strings.Join(req.GetRoles(), ","),
				req.GetState().String(),
				ttl.String(),
			})
		}
		_, err := table.AsBuffer().WriteTo(os.Stdout)
		return trace.Wrap(err)
	} else {
		panic("NOT IMPLEMENTED")
	}
}