using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;

internal class AuthorizationGrantAuthorizationDetailTypeConsentConfiguration : IEntityTypeConfiguration<AuthorizationGrantAuthorizationDetailTypeConsent>
{
    public void Configure(EntityTypeBuilder<AuthorizationGrantAuthorizationDetailTypeConsent> builder)
    {
        builder.HasBaseType<AuthorizationGrantConsent>();
        builder
            .Property(x => x.RawValue)
            .HasMaxLength(1024)
            .IsRequired();
    }
}