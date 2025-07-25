using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;
internal sealed class DeviceCodeConfiguration : IEntityTypeConfiguration<DeviceCode>
{
    public void Configure(EntityTypeBuilder<DeviceCode> builder)
    {
        builder
            .HasOne(x => x.DeviceCodeGrant)
            .WithMany(x => x.DeviceCodes)
            .HasForeignKey("DeviceCodeGrantId")
            .IsRequired(false)
            .OnDelete(DeleteBehavior.ClientCascade);
    }
}