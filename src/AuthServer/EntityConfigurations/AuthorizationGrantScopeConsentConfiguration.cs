using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;

internal sealed class AuthorizationGrantScopeConsentConfiguration : IEntityTypeConfiguration<AuthorizationGrantScopeConsent>
{
    public void Configure(EntityTypeBuilder<AuthorizationGrantScopeConsent> builder)
    {
        builder.HasBaseType<AuthorizationGrantConsent>();
        builder
            .Property(x => x.Resource)
            .HasMaxLength(255)
            .IsRequired();
    }
}