using AuthServer.Extensions;

namespace AuthServer.Tests.UnitTest.Extensions;
public class EnumerableExtensionsTest
{
    [Fact]
    public void IsIntersected_SingleSubset_ExpectTrue()
    {
        // Arrange
        var subset = new List<string> { "x" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.True(subset.IsIntersected(superset));
    }

    [Fact]
    public void IsIntersected_SingleNotSubset_ExpectFalse()
    {
        // Arrange
        var subset = new List<string> { "y" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.False(subset.IsIntersected(superset));
    }

    [Fact]
    public void IsIntersected_MultiPerfectSet_ExpectTrue()
    {
        // Arrange
        var subset = new List<string> { "x", "z" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.True(subset.IsIntersected(superset));
    }

    [Fact]
    public void IsIntersected_MultiNotSubset_ExpectFalse()
    {
        // Arrange
        var subset = new List<string> { "y", "u" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.False(subset.IsIntersected(superset));
    }

    [Fact]
    public void IsIntersected_MultiMixedSubset_ExpectTrue()
    {
        // Arrange
        var subset = new List<string> { "x", "y" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.True(subset.IsIntersected(superset));
    }

    [Fact]
    public void IsIntersected_EmptySubset_ExpectFalse()
    {
        // Arrange
        var subset = new List<string>();
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.False(subset.IsIntersected(superset));
    }

    [Fact]
    public void IsIntersected_EmptySuperset_ExpectFalse()
    {
        // Arrange
        var subset = new List<string> { "x" };
        var superset = new List<string>();

        // Act && Assert
        Assert.False(subset.IsIntersected(superset));
    }

    [Fact]
    public void IsDisjoint_SingleSubset_ExpectFalse()
    {
        // Arrange
        var subset = new List<string> { "x" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.False(subset.IsDisjoint(superset));
    }

    [Fact]
    public void IsDisjoint_SingleNotSubset_ExpectTrue()
    {
        // Arrange
        var subset = new List<string> { "y" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.True(subset.IsDisjoint(superset));
    }

    [Fact]
    public void IsDisjoint_MultiPerfectSet_ExpectFalse()
    {
        // Arrange
        var subset = new List<string> { "x", "z" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.False(subset.IsDisjoint(superset));
    }

    [Fact]
    public void IsDisjoint_MultiNotSubset_ExpectTrue()
    {
        // Arrange
        var subset = new List<string> { "y", "u" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.True(subset.IsDisjoint(superset));
    }

    [Fact]
    public void IsDisjoint_MultiMixedSubset_ExpectFalse()
    {
        // Arrange
        var subset = new List<string> { "x", "y" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.False(subset.IsDisjoint(superset));
    }

    [Fact]
    public void IsDisjoint_EmptySubset_ExpectTrue()
    {
        // Arrange
        var subset = new List<string>();
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.True(subset.IsDisjoint(superset));
    }

    [Fact]
    public void IsDisjoint_EmptySuperset_ExpectTrue()
    {
        // Arrange
        var subset = new List<string> { "x" };
        var superset = new List<string>();

        // Act && Assert
        Assert.True(subset.IsDisjoint(superset));
    }

    [Fact]
    public void IsSubset_SingleSubset_ExpectTrue()
    {
        // Arrange
        var subset = new List<string> { "x" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.True(subset.IsSubset(superset));
    }

    [Fact]
    public void IsSubset_SingleNotSubset_ExpectFalse()
    {
        // Arrange
        var subset = new List<string> { "y" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.False(subset.IsSubset(superset));
    }

    [Fact]
    public void IsSubset_MultiPerfectSet_ExpectTrue()
    {
        // Arrange
        var subset = new List<string> { "x", "z" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.True(subset.IsSubset(superset));
    }

    [Fact]
    public void IsSubset_MultiNotSubset_ExpectFalse()
    {
        // Arrange
        var subset = new List<string> { "y", "u" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.False(subset.IsSubset(superset));
    }

    [Fact]
    public void IsSubset_MultiMixedSubset_ExpectFalse()
    {
        // Arrange
        var subset = new List<string> { "x", "y" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.False(subset.IsSubset(superset));
    }

    [Fact]
    public void IsSubset_EmptySubset_ExpectFalse()
    {
        // Arrange
        var subset = new List<string>();
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.False(subset.IsSubset(superset));
    }

    [Fact]
    public void IsSubset_EmptySuperset_ExpectFalse()
    {
        // Arrange
        var subset = new List<string> { "x" };
        var superset = new List<string>();

        // Act && Assert
        Assert.False(subset.IsSubset(superset));
    }

    [Fact]
    public void IsNotSubset_SingleSubset_ExpectFalse()
    {
        // Arrange
        var subset = new List<string> { "x" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.False(subset.IsNotSubset(superset));
    }

    [Fact]
    public void IsNotSubset_SingleNotSubset_ExpectTrue()
    {
        // Arrange
        var subset = new List<string> { "y" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.True(subset.IsNotSubset(superset));
    }

    [Fact]
    public void IsNotSubset_MultiPerfectSet_ExpectFalse()
    {
        // Arrange
        var subset = new List<string> { "x", "z" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.False(subset.IsNotSubset(superset));
    }

    [Fact]
    public void IsNotSubset_MultiNotSubset_ExpectTrue()
    {
        // Arrange
        var subset = new List<string> { "y", "u" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.True(subset.IsNotSubset(superset));
    }

    [Fact]
    public void IsNotSubset_MultiMixedSubset_ExpectTrue()
    {
        // Arrange
        var subset = new List<string> { "x", "y" };
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.True(subset.IsNotSubset(superset));
    }

    [Fact]
    public void IsNotSubset_EmptySubset_ExpectTrue()
    {
        // Arrange
        var subset = new List<string>();
        var superset = new List<string> { "x", "z" };

        // Act && Assert
        Assert.True(subset.IsNotSubset(superset));
    }

    [Fact]
    public void IsNotSubset_EmptySuperset_ExpectTrue()
    {
        // Arrange
        var subset = new List<string> { "x" };
        var superset = new List<string>();

        // Act && Assert
        Assert.True(subset.IsNotSubset(superset));
    }
}