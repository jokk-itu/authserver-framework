using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;

internal class AuthorizationDetailTypeConsentConfiguration : IEntityTypeConfiguration<AuthorizationDetailTypeConsent>
{
    public void Configure(EntityTypeBuilder<AuthorizationDetailTypeConsent> builder)
    {
        builder.HasBaseType<Consent>();
        builder
            .HasOne(x => x.AuthorizationDetailType)
            .WithMany(x => x.AuthorizationDetailTypeConsents)
            .OnDelete(DeleteBehavior.ClientCascade)
            .IsRequired();
    }
}