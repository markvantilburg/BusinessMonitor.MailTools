﻿namespace BusinessMonitor.MailTools.Bimi
{
    /// <summary>
    /// Represents a BIMI record
    /// </summary>
    public record BimiRecord
    {
        internal BimiRecord()
        {
            Evidence = "";
            Location = null;
        }

        /// <summary>
        /// Gets the location of the Authority Evidence
        /// </summary>
        public string Evidence { get; internal set; }

        /// <summary>
        /// Gets the location of the Brand Indicator file
        /// </summary>
        public string? Location { get; internal set; }
    }
}
