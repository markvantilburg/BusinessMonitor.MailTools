namespace BusinessMonitor.MailTools.Dmarc
{
    [Flags]
    public enum FailureOptions
    {
        None = 0,

        All = 1 << 0,
        Any = 1 << 1,
        DkimFailure = 1 << 2,
        SpfFailure = 1 << 3
    }
}
