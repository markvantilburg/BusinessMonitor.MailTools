namespace BusinessMonitor.MailTools.Spf
{
    /// <summary>
    /// Represents a SPF mechanism
    /// </summary>
    public enum SpfMechanism
    {
        A,
        MX,
        Ptr,
        IP4,
        IP6,
        Exists,
        All,
        Include
    }
}
