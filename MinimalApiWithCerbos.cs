/*
 * =================================================================================
 * .NET 9 Minimal API with Duende + Cerbos (Policy-Based)
 *
 * v4: Added Multi-Tenancy
 *
 * This version introduces tenants.
 * 1. A user's JWT (simulated) lists all tenants they belong to.
 * 2. An API call (simulated) must specify the active tenant.
 * 3. The Auth handler verifies the user is in that tenant.
 * 4. Cerbos policies are now tenant-aware.
 * =================================================================================
 */

using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

// --- .NET Authorization Setup ---
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CanViewAccount", policy =>
        policy.Requirements.Add(new CerbosResourceRequirement("view", "account")));
});

// --- Simulation Services ---
builder.Services.AddSingleton<SimulatedCerbosClient>();
builder.Services.AddSingleton<AccountRepository>();

// --- CUSTOM AUTHORIZATION HANDLER ---
builder.Services.AddSingleton<IAuthorizationHandler, CerbosResourceAuthorizationHandler>();
builder.Services.AddHttpContextAccessor();


var app = builder.Build();

app.UseAuthorization();


// --- API Endpoint (Unchanged) ---
app.MapGet("/accounts/{accountId}",
    async (
        string accountId,
        AccountRepository repo
    ) =>
    {
        var account = repo.GetAccount(accountId);
        if (account is null)
        {
            return Results.NotFound(new { error = "Account not found" });
        }
        return Results.Ok(account);
    })
.WithName("GetAccount")
.RequireAuthorization("CanViewAccount");


app.MapGet("/", () => "API is running. Test with GET /accounts/{accountId}");

app.Run();


// --- Authorization Classes ---

public class CerbosResourceRequirement(string action, string resourceKind) : IAuthorizationRequirement
{
    public string Action { get; } = action;
    public string ResourceKind { get; } = resourceKind;
}

public class CerbosResourceAuthorizationHandler : AuthorizationHandler<CerbosResourceRequirement>
{
    private readonly SimulatedCerbosClient _cerbosClient;
    private readonly AccountRepository _repo;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public CerbosResourceAuthorizationHandler(
        SimulatedCerbosClient cerbosClient,
        AccountRepository repo,
        IHttpContextAccessor httpContextAccessor)
    {
        _cerbosClient = cerbosClient;
        _repo = repo;
        _httpContextAccessor = httpContextAccessor;
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        CerbosResourceRequirement requirement)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext is null)
        {
            context.Fail(); // No HttpContext, can't check
            return;
        }

        // 1. --- AUTHENTICATION & TENANCY (SIMULATED) ---
        /*
         * --- REAL-WORLD CODE ---
         * var user = httpContext.User;
         * var userId = user.FindFirstValue(ClaimTypes.NameIdentifier);
         * var userRoles = user.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
         * var introducerId = user.FindFirstValue("introducer_id")?.Value;
         * var allowedTenants = user.FindAll("tenant_id").Select(c => c.Value).ToList();
         * var activeTenantId = httpContext.Request.Headers["X-Tenant-Id"].FirstOrDefault();
         */
        var userId = httpContext.Request.Headers["X-User-Id"].FirstOrDefault();
        var roles = httpContext.Request.Headers["X-User-Roles"].FirstOrDefault();
        var introducerId = httpContext.Request.Headers["X-User-Introducer-Id"].FirstOrDefault();
        var allowedTenantsHeader = httpContext.Request.Headers["X-User-Tenants"].FirstOrDefault();
        var activeTenantId = httpContext.Request.Headers["X-Tenant-Id"].FirstOrDefault();
        
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(roles) || 
            string.IsNullOrEmpty(allowedTenantsHeader) || string.IsNullOrEmpty(activeTenantId))
        {
            context.Fail(new AuthorizationFailureReason(this, "Missing user, role, or tenant headers"));
            return; // Not authenticated or tenant not specified
        }

        var userRolesList = roles.Split(',').Select(r => r.Trim()).ToList();
        var allowedTenantsList = allowedTenantsHeader.Split(',').Select(t => t.Trim()).ToList();

        // --- TENANCY CHECK 1: Is user allowed to act in this tenant? ---
        if (!allowedTenantsList.Contains(activeTenantId))
        {
            context.Fail(new AuthorizationFailureReason(this, "User not authorized for requested tenant"));
            return;
        }

        // 2. --- FETCH RESOURCE ---
        var accountId = httpContext.GetRouteValue("accountId") as string;
        if (string.IsNullOrEmpty(accountId))
        {
            context.Fail(new AuthorizationFailureReason(this, "Missing accountId in route"));
            return;
        }
        
        var account = _repo.GetAccount(accountId);
        if (account is null)
        {
            context.Fail(new AuthorizationFailureReason(this, "Resource not found"));
            return;
        }

        // 3. --- BUILD CERBOS REQUEST ---
        var principal = new CerbosPrincipal(userId)
        {
            Roles = userRolesList,
            Attributes = new Dictionary<string, object>
            {
                // Pass the *active* tenant to Cerbos for policy checks
                { "activeTenantId", activeTenantId } 
            }
        };

        if (!string.IsNullOrEmpty(introducerId))
        {
            principal.Attributes.Add("introducer_id", introducerId);
        }

        var resource = new CerbosResource(requirement.ResourceKind, account.Id)
        {
            Attributes = new Dictionary<string, object>
            {
                { "ownerId", account.OwnerId },
                // Pass the resource's tenant to Cerbos
                { "tenantId", account.TenantId } 
            }
        };

        // 4. --- AUTHORIZATION (SIMULATED) ---
        var isAllowed = _cerbosClient.IsAllowed(principal, resource, requirement.Action);

        if (isAllowed)
        {
            context.Succeed(requirement);
        }
        else
        {
            context.Fail(new AuthorizationFailureReason(this, "Cerbos check denied access"));
        }
        
        await Task.CompletedTask;
    }
}


// --- Simulation Classes ---

/// <summary>
/// Mock database of accounts. Now includes TenantId.
/// </summary>
public class AccountRepository
{
    private readonly ConcurrentDictionary<string, Account> _accounts = new();

    public AccountRepository()
    {
        // Tenant A accounts
        _accounts.TryAdd("ac_100", new Account("ac_100", "Alice's Primary (Tenant A)", "user_alice", "tenant_A"));
        _accounts.TryAdd("ac_101", new Account("ac_101", "Alice's Savings (Tenant A)", "user_alice", "tenant_A"));
        
        // Tenant B accounts
        _accounts.TryAdd("ac_200", new Account("ac_200", "Bob's Checking (Tenant B)", "user_bob", "tenant_B"));
        _accounts.TryAdd("ac_201", new Account("ac_201", "Alice's Acct (Tenant B)", "user_alice", "tenant_B"));
    }
        
        await Task.CompletedTask;
    }
}


// --- Simulation Classes ---

public class AccountRepository
{
    private readonly ConcurrentDictionary<string, Account> _accounts = new();

    public AccountRepository()
    {
        // Alice owns this account
        _accounts.TryAdd("ac_100", new Account("ac_100", "Alice's Primary Account", "user_alice"));
        _accounts.TryAdd("ac_101", new Account("ac_101", "Alice's Savings", "user_alice"));
        _accounts.TryAdd("ac_200", new Account("ac_200", "Bob's Checking Account", "user_bob"));
    }

    public Account? GetAccount(string id) =>
        _accounts.TryGetValue(id, out var account) ? account : null;
}

// Account record now includes TenantId
public record Account(string Id, string Name, string OwnerId, string TenantId);

/// <summary>
/// This class *simulates* the logic that your Cerbos PDP would execute
/// based on the *UPDATED* 'account_policy.yaml' file.
/// </summary>
public class SimulatedCerbosClient
{
    // Introducer groups are now also tenant-specific
    private readonly Dictionary<string, (string TenantId, List<string> Accounts)> _introducerGroups = new()
    {
        { "group_ingrid_A", ("tenant_A", new List<string> { "ac_101" }) },
        { "group_ingrid_B", ("tenant_B", new List<string> { "ac_200" }) }
    };

    public bool IsAllowed(CerbosPrincipal principal, CerbosResource resource, string action)
    {
        if (resource.Kind != "account" || action != "view")
        {
            return false;
        }

        // --- TENANCY CHECK 2: Resource tenant must match active tenant ---
        // This is the first check in all our simulated rules.
        if (!principal.Attributes.TryGetValue("activeTenantId", out var activeTenantIdObj) ||
            !resource.Attributes.TryGetValue("tenantId", out var resourceTenantIdObj) ||
            activeTenantIdObj as string != resourceTenantIdObj as string)
        {
            return false; // Tenant mismatch
        }
        
        var activeTenantId = activeTenantIdObj as string;

        // Rule 1: "agent" role
        if (principal.Roles.Contains("agent"))
        {
            // The tenant check above is all that's needed for agents.
            return true;
        }

        // Rule 2: "owner"
        if (resource.Attributes.TryGetValue("ownerId", out var ownerId) &&
            ownerId as string == principal.Id)
        {
            // Tenant check already passed.
            return true;
        }

        // Rule 3: "introducer" (Simulating tenant-aware lookup)
        if (principal.Roles.Contains("introducer") &&
            principal.Attributes.TryGetValue("introducer_id", out var introIdObj))
        {
            var introducerId = introIdObj as string;
            if (introducerId != null && 
                _introducerGroups.TryGetValue(introducerId, out var groupData))
            {
                // Check if group's tenant matches active tenant AND
                // if the account is in the group's list.
                if (groupData.TenantId == activeTenantId && 
                    groupData.Accounts.Contains(resource.Id))
                {
                    return true;
                }
            }
        }

        // Deny by default
        return false;
    }
}

// --- Mock Cerbos SDK Classes (Unchanged) ---
public class CerbosPrincipal(string id)
{
    public string Id { get; } = id;
    public List<string> Roles { get; set; } = [];
    public Dictionary<string, object> Attributes { get; set; } = [];
}

public class CerbosResource(string kind, string id)
{
    public string Kind { get; } = kind;
    public string Id { get; } = id;
    public Dictionary<string, object> Attributes { get; set; } = [];
}

