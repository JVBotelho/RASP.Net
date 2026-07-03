using Rasp.Core.Context;
using Xunit;

namespace Rasp.Core.Tests.Context;

public class RaspTaintSensorTests
{
    [Fact]
    public void IsTainted_UnmarkedString_ReturnsFalse()
    {
        var value = "clean-" + System.Guid.NewGuid();
        Assert.False(RaspTaintSensor.IsTainted(value));
    }

    [Fact]
    public void MarkTainted_ThenIsTainted_SameInstance_ReturnsTrue()
    {
        var value = "tainted-" + System.Guid.NewGuid();
        RaspTaintSensor.MarkTainted(value);

        Assert.True(RaspTaintSensor.IsTainted(value));
    }

    [Fact]
    public void MarkTainted_DoesNotTaintEqualButDistinctInstance()
    {
        // string.Copy is obsolete but is exactly what we need here: force a distinct
        // object instance with equal content, since the interned literal below would
        // otherwise collide with any other test using the same text.
        var original = "distinct-instance-" + System.Guid.NewGuid();
        var copy = new string(original.ToCharArray());

        RaspTaintSensor.MarkTainted(original);

        Assert.True(RaspTaintSensor.IsTainted(original));
        Assert.False(RaspTaintSensor.IsTainted(copy));
    }

    [Fact]
    public void PropagateTaint_NeitherOperandTainted_ResultNotTainted()
    {
        var arg0 = "clean0-" + System.Guid.NewGuid();
        var arg1 = "clean1-" + System.Guid.NewGuid();
        var result = arg0 + arg1;

        RaspTaintSensor.PropagateTaint(result, arg0, arg1);

        Assert.False(RaspTaintSensor.IsTainted(result));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void PropagateTaint_EitherOperandTainted_ResultBecomesTainted(bool taintArg0, bool taintArg1)
    {
        var arg0 = "op0-" + System.Guid.NewGuid();
        var arg1 = "op1-" + System.Guid.NewGuid();
        var result = "concat-result-" + System.Guid.NewGuid();

        if (taintArg0) RaspTaintSensor.MarkTainted(arg0);
        if (taintArg1) RaspTaintSensor.MarkTainted(arg1);

        RaspTaintSensor.PropagateTaint(result, arg0, arg1);

        Assert.True(RaspTaintSensor.IsTainted(result));
    }

    [Fact]
    public void MarkTainted_NullOrEmpty_DoesNotThrow()
    {
        RaspTaintSensor.MarkTainted(null);
        RaspTaintSensor.MarkTainted(string.Empty);

        Assert.False(RaspTaintSensor.IsTainted(null));
        Assert.False(RaspTaintSensor.IsTainted(string.Empty));
    }
}
