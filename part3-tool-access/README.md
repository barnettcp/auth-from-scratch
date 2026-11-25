# Part 3 — Tool Access and Authorization

This part of the repository shifts from "who is this person?" to "what is this person allowed to do?"

Authentication and authorization are related, but they are not the same thing:

- Authentication answers: "Who is this caller?"
- Authorization answers: "Is this caller allowed to invoke this action on this resource?"

The examples in the earlier parts of this repository focus on proving identity using keys, signatures, and JWTs. This part is about the boundary where identity becomes action.

## Why this matters

Once a user is logged in, a real system still has to answer questions like:

- Can this user access this tool at all?
- Can they use only a subset of tools?
- Can they read a document, but not modify it?
- Can they invoke a tool on one project, but not another?
- Can the system call a tool as the user, or only as a service account?

This is the same conceptual issue behind many modern tool or API authorization patterns, including agent/tool gateways, internal APIs, and large language model tool use.

## The idea: identity plus policy

A simple mental model is:

```
User identity         +   policy decision   +   resource + action
       |                     |                    |           |
       v                     v                    v           v
   "who are you?"      "are you allowed?"     "what are you touching?" 
```

The flow is usually:

1. A user authenticates and receives a signed identity token.
2. The application or tool gateway reads the token and identifies the subject.
3. The system checks policy: user, role, group, tenant, resource, tool name, and action.
4. If allowed, the action is executed.
5. If denied, the call fails with a clear authorization failure.

## A toy example: authenticated user, restricted tool access

Imagine the same basic identity flow from Part 2, but now the authenticated user is not just "logged in" — they are also a subject with tool permissions.

Example users:

- `alice`: authenticated user, allowed to read notes, not allowed to delete notes
- `bob`: authenticated user, allowed to read and write notes
- `charlie`: authenticated user, no tool access at all
- `admin`: authenticated user, allowed to manage tools and resources

Example tools:

- `read_note`
- `write_note`
- `delete_note`
- `list_projects`
- `deploy_release`

Example policy rules:

- `alice` may call `read_note` on project `team-alpha`
- `alice` may not call `delete_note`
- `bob` may call `read_note` and `write_note` on `team-alpha`
- `admin` may call `deploy_release`
- `charlie` may not call anything unless explicitly granted

This produces the key production pattern:

- Authentication proves the user's identity.
- Authorization decides whether that identity may invoke a given operation on a resource.

## Why this is useful for MCP-like systems

This isn't really a "MCP feature" so much as a general engineering pattern.

A system that exposes tools to an authenticated user should behave like this:

- The user authenticates as themselves.
- The tool gateway checks whether that identity is allowed to invoke that specific tool.
- The request is executed only if policy says yes.
- Denied requests should explain why, not silently fail.

This is the principle behind many agent and tool authorization patterns:

- user identity is not enough
- tool access must be scoped and explicit
- policy enforcement should happen at the boundary where the tool is executed

## A simple illustrative flow

A minimal conceptual flow for a tool call looks like this:

```
Browser / client
      |
      v
Authenticate user
      |
      v
Receive signed identity token
      |
      v
Call tool endpoint with token + tool name + target resource
      |
      v
Tool gateway verifies token and checks policy
      |
      +-- allowed --> execute tool
      |
      +-- denied --> return 403 / access denied / reason
```

Notice the distinction here:

- The token proves identity.
- The policy check decides whether access is granted.
- The tool execution is the final enforcement point.

## What this repository should teach here

This part should stay intentionally small and illustrative. The goal is not to build a production authZ system. The goal is to teach the shape of the idea.

The tutorial should demonstrate:

1. A user logs in successfully.
2. The caller is recognized as a specific principal.
3. A tool is invoked.
4. The system checks whether that principal is authorized for that tool.
5. The tool is allowed or denied.
6. The trace clearly distinguishes between identity and authorization.

## Suggested teaching examples

Good examples for the repo:

- `alice` can read notes but cannot delete them
- `bob` can write notes but cannot deploy releases
- `admin` can do both
- an unauthenticated user cannot call any tools
- an authenticated user without a policy entry gets a clear denial

These examples are simple enough to understand, but they mirror the real shape of production access control.

## Relationship to the rest of the repo

This part should feel like a natural continuation of the earlier material:

- Part 1 shows how keys, signatures, and JWTs create trustable identity.
- Part 2 shows how an app and IdP exchange and verify identity over HTTP.
- Part 3 shows how those identities become permissioned actions at the tool boundary.

This is the same progression used in real systems:

- prove identity
- verify identity
- enforce policy
- allow or deny actions

## Next steps

The next step after this conceptual part is to add an illustrative notebook, likely `08_...`, which would walk through:

- a user authenticating as themselves
- a policy table for tool access
- a tool gateway that checks authorization before execution
- a few success and failure scenarios

This notebook should stay illustrative and teaching-oriented rather than production-ready.
