module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: 'Mandiant Threat Intelligence',
  /**
   * The acronym that appears in the notification window when information from this integration
   * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
   * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
   * here will be carried forward into the notification window.
   *
   * @type String
   * @required
   */
  acronym: 'MTI',
  onDemandOnly: true,
  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description:
    'Provides automated access to indicators of compromise (IOCs), CVE information, as well as information on threat actor names from the Mandiant Threat Intelligence API.',
  entityTypes: ['IPv4', 'domain', 'email', 'MD5', 'SHA1', 'SHA256', 'cve', 'url'],
  customTypes: [
    {
      key: 'allText',
      regex: /\S[\s\S]{3,30}\S/
    },
    {
      key: 'threatActor',
      regex:
        /APT\d{0,6}|FIN\d{0,6}|UNC\d{0,6}|TEMP\.\w{1,25}|Ajax Team|Barista Team|Bolo Team|Conference Crew|Conimes Team|Fallout Team|Havildar Team|Koala Team|Molerats|Naikon Team|Roaming Tiger|Ace|Andromeda|Armageddon|Avengers|Batis|Beanie|Bengal|Demon|DragonOK|Hermit|Hex|Isotope|Jafar|Katar|Lice|MetaStrike|MixMaster|Omega|Overboard|Scimitar|Shadow|Splinter|Tick|Toucan|Traveler|Trident|TruthTeller|Vermin|Zagros|Zombie|Team 338|Termite Team|Tonto Team|Turla Team|ZeroWing Team/
    }
  ],
  /**
   * An array of style files (css or less) that will be included for your integration. Any styles specified in
   * the below files can be used in your custom template.
   *
   * @type Array
   * @optional
   */
  styles: ['./styles/styles.less'],
  /**
   * Provide custom component logic and template for rendering the integration details block.  If you do not
   * provide a custom template and/or component then the integration will display data as a table of key value
   * pairs.
   *
   * @type Object
   * @optional
   */
  block: {
    component: {
      file: './components/block.js'
    },
    template: {
      file: './templates/block.hbs'
    }
  },
  defaultColor: 'dark-pink',
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: ''
  },
  logging: {
    level: 'info' //trace, debug, info, warn, error, fatal
  },
  /**
   * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
   * as an array of option objects.
   *
   * @type Array
   * @optional
   */
  options: [
    {
      key: 'urlV4',
      name: 'Mandiant URL',
      description:
        'The URL for the Mandiant Threat Intelligence V4 API.  Defaults to `https://api.intelligence.mandiant.com`.',
      default: 'https://api.intelligence.mandiant.com',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'publicKey',
      name: 'Public Key',
      description: 'Your Mandiant Threat Intelligence API public key',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'privateKey',
      name: 'Private Key',
      description: 'Your Mandiant Threat Intelligence API private key.',
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'minimumMScore',
      name: 'Minimum ThreatScore to Display',
      description:
        'The minimum ThreatScore (0-100) required for indicators to be displayed [default is 60].  Indicators with a ThreatScore above 60 are considered malicious.',
      default: 60,
      type: 'number',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'enableThreatActorSearch',
      name: 'Enable Threat Actor Search',
      description: 'If checked, the integration will search threat actors by name.',
      default: true,
      type: 'boolean',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'getThreatActorAssociatedAttackPatternsAndReports',
      name: 'Get Threat Actor associated Attack Patterns and Reports',
      description:
        'If checked, the integration will get associated Attack Patterns and Reports by found Threat Actors in `Threat Actors` and `Search` Tabs.',
      default: true,
      type: 'boolean',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'vulnerabilityRatingSources',
      name: 'Vulnerability Rating Sources',
      description:
        'Only return results for Vulnerabilities that come from the Rating Sources selected here.',
      type: 'select',
      default: [
        {
          value: 'analyst',
          display: 'Analysts'
        },
        {
          value: 'predicted',
          display: 'Machine Learning'
        },
        {
          value: 'unrated',
          display: 'Unrated'
        }
      ],
      options: [
        {
          value: 'analyst',
          display: 'Analysts'
        },
        {
          value: 'predicted',
          display: 'Machine Learning'
        },
        {
          value: 'unrated',
          display: 'Unrated'
        }
      ],
      multiple: true,
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'searchResultsType',
      name: 'Search Results Type',
      description:
        'Search Results returns for Indicators, Malware, Reports, Threat Actors, and Vulnerabilities. Use this to limit the Search Results to just one specific Type, `All` types, or disable the Search Results with `None`.',
      type: 'select',
      default: {
        value: 'all',
        display: 'All'
      },
      options: [
        {
          value: 'all',
          display: 'All'
        },
        {
          value: 'indicator',
          display: 'Indicators'
        },
        {
          value: 'malware',
          display: 'Malware'
        },
        {
          value: 'report',
          display: 'Reports'
        },
        {
          value: 'threat-actor',
          display: 'Threat Actors'
        },
        {
          value: 'vulnerability',
          display: 'Vulnerabilities'
        },
        {
          value: 'none',
          display: 'None'
        }
      ],
      multiple: false,
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'blocklist',
      name: 'Ignored Entities',
      description:
        'Comma separated list of entities that you never want looked up. Should be set to "Only admins can view and edit".',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'domainBlocklistRegex',
      name: 'Ignored Domains Regex',
      description:
        'Domains that match the given regex will not be looked up (if blank, no domains will be black listed).  Should be set to "Only admins can view and edit".',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'maxConcurrent',
      name: 'Max Concurrent Requests',
      description:
        'Maximum number of concurrent requests.  Integration must be restarted after changing this option. Defaults to 20.',
      default: 20,
      type: 'number',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'minTime',
      name: 'Minimum Time Between Lookups',
      description:
        'Minimum amount of time in milliseconds between lookups. Integration must be restarted after changing this option. Defaults to 100.',
      default: 100,
      type: 'number',
      userCanEdit: false,
      adminOnly: true
    }
  ]
};
