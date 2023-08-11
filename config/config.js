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
  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description:
    'Provides automated access to indicators of compromise (IOCs), CVE information, as well as information on the adversary from the Mandiant Threat Intelligence API.',
  entityTypes: ['IPv4', 'domain', 'email', 'hash', 'cve'],
  customTypes: [
    {
      key: 'allText',
      regex: /\S[\s\S]{3,30}\S/
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
  onDemandOnly: false,
  /**
   * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
   * as an array of option objects.
   *
   * @type Array
   * @optional
   */
  options: [
    {
      key: 'apiQueryVersion',
      name: 'API Query Version',
      description: 'Which Version of the API(s) to query: V3, V4, or both.',
      default: {
        value: 'v3',
        display: 'V3'
      },
      type: 'select',
      options: [
        {
          value: 'v3',
          display: 'V3'
        },
        {
          value: 'v4',
          display: 'V4'
        },
        {
          value: 'v3v4',
          display: 'V3 & V4'
        }
      ],
      multiple: false,
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'urlV3',
      name: 'Mandiant V3 URL',
      description:
        'The URL for the Mandiant Threat Intelligence V3 API.  Defaults to `https://api.intelligence.fireeye.com`.',
      default: 'https://api.intelligence.fireeye.com',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },

    {
      key: 'publicKeyV3',
      name: 'V3 Public Key',
      description: 'Your Mandiant Threat Intelligence V3 API public key',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'privateKeyV3',
      name: 'V3 Private Key',
      description: 'Your Mandiant Threat Intelligence V3 API private key.',
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: true
    },

    {
      key: 'urlV4',
      name: 'Mandiant V4 URL',
      description:
        'The URL for the Mandiant Threat Intelligence V4 API.  Defaults to `https://api.intelligence.mandiant.com`.',
      default: 'https://api.intelligence.mandiant.com',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'publicKeyV4',
      name: 'V4 Public Key',
      description: 'Your Mandiant Threat Intelligence V4 API public key',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'privateKeyV4',
      name: 'V4 Private Key',
      description: 'Your Mandiant Threat Intelligence V4 API private key.',
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'minimumMScore',
      name: 'Minimum MScore to Display',
      description:
        'The minimum MScore (0-100) required for indicators to be displayed [default is 51].  Indicators with a MScore above 50 are considered suspicious and/or malicious.',
      default: 51,
      type: 'number',
      userCanEdit: false,
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
