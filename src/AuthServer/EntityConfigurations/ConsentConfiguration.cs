using AuthServer.Entities;
using AuthServer.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;

internal sealed class ConsentConfiguration : IEntityTypeConfiguration<Consent>
{
    public void Configure(EntityTypeBuilder<Consent> builder)
    {
        builder
            .HasDiscriminator(x => x.ConsentType)
            .HasValue<ScopeConsent>(ConsentType.Scope)
            .HasValue<ClaimConsent>(ConsentType.Claim);
        
        builder
            .HasOne(x => x.Client)
            .WithMany(x => x.Consents)
            .IsRequired()
            .OnDelete(DeleteBehavior.ClientCascade);

        builder
            .HasOne(x => x.SubjectIdentifier)
            .WithMany(x => x.Consents)
            .IsRequired()
            .OnDelete(DeleteBehavior.ClientCascade);
    }
}