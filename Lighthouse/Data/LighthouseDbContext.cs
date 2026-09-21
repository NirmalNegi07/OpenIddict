using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;

namespace Lighthouse.Data;

public class LighthouseDbContext : IdentityDbContext<IdentityUser>
{
    public LighthouseDbContext(DbContextOptions<LighthouseDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Registers the OpenIddict entity sets (applications, authorizations, scopes, tokens)
        // on top of the ASP.NET Core Identity tables already mapped by IdentityDbContext.
        builder.UseOpenIddict();

        // MySQL's InnoDB caps a composite index key at 3072 bytes. With utf8mb4 (4 bytes/char),
        // OpenIddict's default column lengths on Authorizations/Tokens blow past that on the
        // Status/Subject/Type index, so they're trimmed down here to fit.
        builder.Entity<OpenIddictEntityFrameworkCoreAuthorization>(entity =>
        {
            entity.Property(a => a.Status).HasMaxLength(50);
            entity.Property(a => a.Subject).HasMaxLength(200);
            entity.Property(a => a.Type).HasMaxLength(50);
        });

        builder.Entity<OpenIddictEntityFrameworkCoreToken>(entity =>
        {
            entity.Property(t => t.Status).HasMaxLength(50);
            entity.Property(t => t.Subject).HasMaxLength(200);
            entity.Property(t => t.Type).HasMaxLength(150);
            entity.Property(t => t.ReferenceId).HasMaxLength(100);
        });
    }
}
