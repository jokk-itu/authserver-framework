using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;
internal sealed class DPoPNonceConfiguration : IEntityTypeConfiguration<DPoPNonce>
{
    public void Configure(EntityTypeBuilder<DPoPNonce> builder)
    {
        builder
            .HasOne(x => x.Client)
            .WithMany(x => x.Nonces)
            .IsRequired()
            .OnDelete(DeleteBehavior.Cascade);
    }
}
