using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;
internal class DeviceCodeConfiguration : IEntityTypeConfiguration<DeviceCode>
{
    public void Configure(EntityTypeBuilder<DeviceCode> builder)
    {
        builder
            .HasOne(x => x.DeviceCodeGrant)
            .WithMany(x => x.DeviceCodes)
            .IsRequired(false)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
