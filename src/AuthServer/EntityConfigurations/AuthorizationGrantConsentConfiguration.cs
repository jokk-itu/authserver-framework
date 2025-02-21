using AuthServer.Entities;
using AuthServer.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;

public class AuthorizationGrantConsentConfiguration : IEntityTypeConfiguration<AuthorizationGrantConsent>
{
    public void Configure(EntityTypeBuilder<AuthorizationGrantConsent> builder)
    {
        builder
            .HasDiscriminator(x => x.ConsentType)
            .HasValue<AuthorizationGrantScopeConsent>(ConsentType.Scope)
            .HasValue<AuthorizationGrantClaimConsent>(ConsentType.Claim);

        builder
            .HasOne(x => x.Consent)
            .WithMany(x => x.AuthorizationGrantConsents)
            .IsRequired()
            .OnDelete(DeleteBehavior.Cascade);

        builder
            .HasOne(x => x.AuthorizationGrant)
            .WithMany(x => x.AuthorizationGrantConsents)
            .IsRequired()
            .OnDelete(DeleteBehavior.Cascade);
    }
}