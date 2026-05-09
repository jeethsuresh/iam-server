You are building a distributed IAM + Matrix + realtime communications platform in Elixir/Phoenix.

The system combines:
- IAM / identity management
- RBAC + scoped permissions
- Matrix messaging
- WebRTC session orchestration
- persistent websocket infrastructure
- room/process orchestration
- distributed realtime state

This system should be architected in an extremely idiomatic Elixir/OTP style.

# Core Architectural Principles

- Use OTP primitives heavily.
- Prefer GenServers, DynamicSupervisors, Registries, ETS, PubSub, and process isolation.
- Rooms should behave like distributed actors/processes.
- Keep bounded contexts separated.
- Design for clustering eventually, even if single-node initially.
- Avoid tightly coupling Matrix, IAM, and WebRTC logic together.
- Prefer explicit interfaces between subsystems.

# Tech Stack

Core:
- Elixir
- Phoenix
- Phoenix Channels
- Ecto
- PostgreSQL

Realtime:
- Phoenix PubSub
- Registry
- DynamicSupervisor
- Presence

Distributed:
- libcluster
- Horde or Swarm (later)

Auth:
- JOSE/Joken or Guardian
- Argon2 password hashing

Media:
- WebRTC signaling only inside Elixir
- Media transport handled externally (LiveKit preferred)
- Elixir orchestrates SDP/ICE/session lifecycle

# System Modules

Create bounded contexts/modules for:

- IAM
- Authorization
- Matrix
- Rooms
- Presence
- Calls
- Federation (future)
- Realtime
- Resources

Do NOT create a giant monolith namespace.

# IAM Design

Everything authenticatable is a Principal.

Principal types:
- user
- service
- bot
- agent

A Principal may have:
- multiple credentials
- multiple roles
- scoped permissions

Credentials must be separate from principals.

Support:
- password
- API key
- OAuth
- mTLS/public key auth

# RBAC Design

Authorization must support:
- global roles
- room-scoped roles
- resource-scoped roles

Resources are generic and ARN-like.

Examples:
- arn:lakehouse:matrix:room:123
- arn:lakehouse:call:session:abc
- arn:lakehouse:tenant:xyz

Authorization model:
- Principal
- Role
- Permission
- Resource
- Grant
- Policy

Never hardcode permissions directly into user records.

# Required Authorization APIs

Implement APIs similar to:

IAM.can?(principal, action, resource)
IAM.assign_role(principal, role, resource)
IAM.revoke_role(principal, role, resource)
IAM.permissions_for(principal)
IAM.roles_for(principal)
IAM.resources_for(principal)

Authorization checks must eventually support ETS caching.

# Matrix Design

Do NOT implement Matrix federation initially.

Instead:
- build Matrix-compatible room/event infrastructure
- support websocket and HTTP polling
- support Matrix-style room semantics
- support event timelines
- support room membership state

Each room should eventually map to a supervised process.

# Room Process Model

Rooms are long-lived processes.

Each room process should maintain:
- presence
- active websocket clients
- typing indicators
- media session state
- room membership cache
- event timeline cache
- ICE negotiation state

Use:
- DynamicSupervisor
- Registry
- PubSub

# Websocket Architecture

Use Phoenix Channels.

Flow:
client socket
→ room channel
→ room process

Avoid putting business logic directly inside channel handlers.

# WebRTC Architecture

Elixir is ONLY responsible for:
- signaling
- SDP exchange
- ICE exchange
- session lifecycle
- permissions
- orchestration

Do NOT attempt to relay media through Phoenix.

Assume LiveKit integration later.

# Database Design

Generate Ecto schemas and migrations for:

Core:
- principals
- credentials
- roles
- permissions
- role_permissions
- grants
- resources

Realtime:
- rooms
- room_memberships
- room_events
- room_state
- call_sessions
- webrtc_peers

Use UUIDs everywhere.

# Coding Style

- Prefer explicit typespecs.
- Prefer small focused modules.
- Avoid “god modules”.
- Avoid hidden magic.
- Prefer pure functions outside GenServers.
- Use behaviours/interfaces where appropriate.
- Write supervision trees cleanly.
- Build composable contexts.

# Important Constraints

- Design for high concurrency.
- Design for fault isolation.
- Design for horizontal scaling later.
- Avoid synchronous bottlenecks.
- Avoid shared mutable state.
- Prefer message passing.
- Use ETS carefully and intentionally.
- Avoid premature federation complexity.

# Initial Milestone

Generate:
1. Phoenix umbrella app architecture
2. IAM bounded context
3. RBAC models and APIs
4. JWT authentication flow
5. Room CRUD APIs
6. Room process supervision tree
7. Phoenix Channel room communication
8. Presence tracking
9. Authorization middleware/plugs
10. Clean project structure

# Deliverables

As code is generated:
- explain architectural decisions briefly
- keep modules production-oriented
- generate idiomatic Elixir
- include migrations
- include supervision trees
- include behaviours/interfaces when useful
- include tests for critical authorization logic

When uncertain:
- prioritize extensibility
- prioritize OTP correctness
- prioritize distributed-system friendliness
- prioritize composability
- avoid shortcuts that limit future clustering
