﻿using System.Net;

namespace BusinessMonitor.MailTools.Spf
{
    /// <summary>
    /// Represents a SPF directive
    /// </summary>
    public record SpfDirective
    {
        internal SpfDirective(SpfQualifier qualifier, SpfMechanism mechanism)
        {
            Qualifier = qualifier;
            Mechanism = mechanism;

            Include = null;
            Included = null;
            IP4 = null;
            IP6 = null;
            Domain = null;
            Addresses = new IPAddress[0];
        }

        /// <summary>
        /// Gets the qualifier
        /// </summary>
        public SpfQualifier Qualifier { get; set; }

        /// <summary>
        /// Gets the mechanism
        /// </summary>
        public SpfMechanism Mechanism { get; set; }

        /// <summary>
        /// Gets the include domain for an include mechanism
        /// </summary>
        public string? Include { get; set; }

        /// <summary>
        /// Gets the included record, this will be null if no lookup was done
        /// </summary>
        public SpfRecord? Included { get; set; }

        /// <summary>
        /// Gets the IPv4 address for a IP4 mechanism
        /// </summary>
        public SpfAddress? IP4 { get; set; }

        /// <summary>
        /// Gets the IPv6 address for a IP6 mechanism
        /// </summary>
        public SpfAddress? IP6 { get; set; }

        /// <summary>
        /// Gets the domain for the A or MX mechanism
        /// </summary>
        public string? Domain { get; set; }

        /// <summary>
        /// Gets the addresses for the A or MX mechanism
        /// </summary>
        public IPAddress[] Addresses { get; set; }
    }
}
