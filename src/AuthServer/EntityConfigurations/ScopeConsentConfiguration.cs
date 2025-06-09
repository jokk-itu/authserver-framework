using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;

internal sealed class ScopeConsentConfiguration : IEntityTypeConfiguration<ScopeConsent>
{
    public void Configure(EntityTypeBuilder<ScopeConsent> builder)
    {
        builder.HasBaseType<Consent>();
        builder
            .HasOne(x => x.Scope)
            .WithMany(x => x.ScopeConsents)
            .OnDelete(DeleteBehavior.ClientCascade)
            .IsRequired();
    }
}