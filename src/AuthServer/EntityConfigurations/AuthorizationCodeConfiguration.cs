using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;
internal sealed class AuthorizationCodeConfiguration : IEntityTypeConfiguration<AuthorizationCode>
{
    public void Configure(EntityTypeBuilder<AuthorizationCode> builder)
    {
        builder
            .HasOne(x => x.AuthorizationCodeGrant)
            .WithMany(x => x.AuthorizationCodes)
            .HasForeignKey("AuthorizationCodeGrantId")
            .IsRequired()
            .OnDelete(DeleteBehavior.ClientCascade);
    }
}