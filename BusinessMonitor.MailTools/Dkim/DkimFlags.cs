namespace BusinessMonitor.MailTools.Dkim
{
    [Flags]
    public enum DkimFlags
    {
        None = 0,

        Testing = 1 << 0,
        SameDomain = 1 << 1,
    }
}
