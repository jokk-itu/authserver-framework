using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;
internal sealed class AuthorizationGrantNonceConfiguration : IEntityTypeConfiguration<AuthorizationGrantNonce>
{
    public void Configure(EntityTypeBuilder<AuthorizationGrantNonce> builder)
    {
        builder
            .HasOne(x => x.AuthorizationGrant)
            .WithMany(x => x.Nonces)
            .IsRequired()
            .OnDelete(DeleteBehavior.Cascade);
    }
}
