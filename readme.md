# .NET 9 API with Duende and Cerbos (v4: Multi-Tenant "Pull" Pattern)

This project demonstrates a scalable, multi-tenant, policy-based approach.

## The Multi-Tenant "Pull" Pattern

This builds on the "pull" pattern by adding a crucial layer of tenant isolation:

1.  **Small JWT:** The Duende token is small. It provides:
    * `user_id: "user_alice"`
    * `roles: ["user", "introducer"]`
    * `tenants: ["tenant_A", "tenant_B"]` (All tenants the user can access)
    * `introducer_id: "group_ingrid_A"` (Their group ID for tenant A)
    * `introducer_id: "group_ingrid_B"` (Their group ID for tenant B)
    *(Note: In a real JWT, claims can be repeated, so having multiple `introducer_id` claims is valid).*

2.  **API Call:** The user *must* specify which tenant they are acting in via an `X-Tenant-Id` header.

3.  **C# `AuthorizationHandler`:** The handler performs the first critical check:
    * It gets the `X-Tenant-Id: "tenant_A"` from the header.
    * It gets the `X-User-Tenants: "tenant_A,tenant_B"` (simulated claims).
    * It verifies that the active tenant is in the user's allowed list. **If not, the request is denied.**

4.  **Cerbos Policy (`account_policy.yaml`):** All policies are now tenant-aware.
    * It checks that the resource's tenant matches the user's active tenant (`R.attr.tenantId == P.attr.activeTenantId`).
    * The `introducer_access` rule looks up the `introducer_group` and *also* verifies that the group's `tenantId` matches the user's active tenant.

5.  **Cerbos Data (`introducer_group.yaml`):** This data is now tenant-specific. `group_ingrid_A` is linked to `tenant_A` and only lists accounts in `tenant_A`.

This provides two-level protection:

1.  **Application Level (C#):** Are you allowed to even *be* in this tenant?
2.  **Policy Level (Cerbos):** Now that you're in this tenant, what can you *do*?

## How to Run the Simulation

1.  Make sure you have the .NET 9 SDK installed.
2.  Save `Program.cs` to a directory.
3.  Run the application:
    ```sh
    dotnet run
    ```

## How to Test (Updated for Tenancy)

All commands now require `X-Tenant-Id` and `X-User-Tenants`.

**Our Mock Data:**
* `ac_100`: Owned by `user_alice` in `tenant_A`
* `ac_101`: Owned by `user_alice` in `tenant_A`
* `ac_200`: Owned by `user_bob` in `tenant_B`
* `ac_201`: Owned by `user_alice` in `tenant_B`
* `group_ingrid_A`: (In `tenant_A`) Can access `ac_101`
* `group_ingrid_B`: (In `tenant_B`) Can access `ac_200`

---

### Test 1: Alice (Owner in Correct Tenant)
Alice is in `tenant_A` and accesses her own account `ac_100` (also in `tenant_A`).
**Rule:** Matches "owner_access_tenant".
**Result:** **Allow** (HTTP 200)

```sh
curl -i \
  -H "X-User-Id: user_alice" \
  -H "X-User-Roles: user" \
  -H "X-User-Tenants: tenant_A,tenant_B" \
  -H "X-Tenant-Id: tenant_A" \
  "http://localhost:5123/accounts/ac_100"
```

**Response:** `HTTP/1.1 200 OK ... {"id":"ac_100", ... "tenantId":"tenant_A"}`

---

### Test 2: Alice (Owner, but WRONG Tenant)
Alice is acting in `tenant_B`, but tries to access her account `ac_100` (which is in `tenant_A`).
**Rule:** Fails tenant check (`P.attr.activeTenantId == R.attr.tenantId`).
**Result:** **Deny** (HTTP 403)

```sh
curl -i \
  -H "X-User-Id: user_alice" \
  -H "X-User-Roles: user" \
  -H "X-User-Tenants: tenant_A,tenant_B" \
  -H "X-Tenant-Id: tenant_B" \
  "http://localhost:5123/accounts/ac_100"
```

**Response:** `HTTP/1.1 403 Forbidden`

---

### Test 3: Alice (Access Denied - Not in Tenant)
Alice is only in `tenant_A`, but tries to act in `tenant_B`.
**Rule:** Fails C# `AuthorizationHandler` check (active tenant not in allowed list).
**Result:** **Deny** (HTTP 403)

```sh
curl -i \
  -H "X-User-Id: user_alice" \
  -H "X-User-Roles: user" \
  -H "X-User-Tenants: tenant_A" \
  -H "X-Tenant-Id: tenant_B" \
  "http://localhost:5123/accounts/ac_200"
```

**Response:** `HTTP/1.1 403 Forbidden`

---

### Test 4: Ingrid (Introducer in Correct Tenant)
Ingrid acts in `tenant_B` with her `group_ingrid_B` ID. She accesses `ac_200`.
**Rule:** Matches "introducer_access_tenant".
**Result:** **Allow** (HTTP 200)

```sh
curl -i \
  -H "X-User-Id: user_ingrid" \
  -H "X-User-Roles: introducer" \
  -H "X-User-Tenants: tenant_A,tenant_B" \
  -H "X-Tenant-Id: tenant_B" \
  -H "X-User-Introducer-Id: group_ingrid_B" \
  "http://localhost:5123/accounts/ac_200"
```

**Response:** `HTTP/1.1 200 OK ... {"id":"ac_200", ... "tenantId":"tenant_B"}`

---

### Test 5: Ingrid (Introducer, Tenant Mismatch)
Ingrid acts in `tenant_A` but tries to use her `group_ingrid_B` ID.
**Rule:** "introducer_access_tenant" fails (group's tenant `tenant_B` != active tenant `tenant_A`).
**Result:** **Deny** (HTTP 403)

```sh
curl -i \
  -H "X-User-Id: user_ingrid" \
  -H "X-User-Roles: introducer" \
  -H "X-User-Tenants: tenant_A,tenant_B" \
  -H "X-Tenant-Id: tenant_A" \
  -H "X-User-Introducer-Id: group_ingrid_B" \
  "http://localhost:5123/accounts/ac_101"
```

**Response:** `HTTP/1.1 403 Forbidden`
    
