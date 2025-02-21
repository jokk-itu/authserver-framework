using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;

public class ClaimConsentConfiguration : IEntityTypeConfiguration<ClaimConsent>
{
    public void Configure(EntityTypeBuilder<ClaimConsent> builder)
    {
        builder.HasBaseType<Consent>();
        builder
            .HasOne(x => x.Claim)
            .WithMany(x => x.ClaimConsents)
            .OnDelete(DeleteBehavior.ClientCascade)
            .IsRequired();
    }
}