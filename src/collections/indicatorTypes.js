const _ = require('lodash');

const BASE_WEB_URL = 'https://intelligence.fireeye.com';

const legacyTypes = {
  malware: {
    displayValue: 'Malware',
    icon: 'bug',
    order: 3,
    getFields: (malware) => {
      return {
        link: {
          display: 'Search in FireEye Intel',
          url: `${BASE_WEB_URL}/search?search=malware%20is%20${malware.name}`
        },
        fields: [
          {
            key: 'Name',
            value: malware.name
          },
          {
            key: 'Labels',
            value: Array.isArray(malware.labels) ? malware.labels : []
          },
          {
            key: 'Malware Types',
            value: Array.isArray(malware.malware_types) ? malware.malware_types : []
          },
          {
            key: 'Is Family',
            value: malware.is_family
          },
          {
            key: 'OS Execution Envs',
            value: Array.isArray(malware.os_execution_envs) ? malware.os_execution_envs : []
          },
          {
            key: 'Associated Detection Names',
            nested: true,
            value: malware.x_fireeye_com_associated_detection_names
          },
          {
            key: 'Description',
            value: malware.description
          }
        ]
      };
    }
  },
  indicator: {
    displayValue: 'Indicators',
    icon: 'bullseye',
    order: 1,
    getFields: (indicator, entityObj) => {
      return {
        link: {
          display: 'Search in FireEye Intel',
          url: `${BASE_WEB_URL}/search?search=indicator%20${entityTypeToIndicatorType(entityObj)}%20is${
            entityObj.value
          }`
        },
        fields: [
          {
            key: 'Types',
            value: indicator.indicator_types
          },
          {
            key: 'Confidence',
            value: indicator.confidence
          },
          {
            key: 'Pattern',
            value: indicator.pattern
          },
          {
            key: 'Labels',
            value: indicator.labels
          },
          {
            key: 'Metadata',
            nested: true,
            value: indicator.x_fireeye_com_metadata
          }
        ]
      };
    }
  },
  'threat-actor': {
    displayValue: 'Threat Actors',
    icon: 'user-secret',
    order: 2,
    getFields: (actor) => {
      return {
        link: {
          display: 'Search in FireEye Intel',
          url: `${BASE_WEB_URL}/search?search=actor%20is%20${actor.name}&exclude_indicator_reports=false`
        },
        fields: [
          {
            key: 'Name',
            value: actor.name
          },

          {
            key: 'id',
            value: actor.id
          },
          {
            key: 'Labels',
            value: Array.isArray(actor.labels) ? actor.labels : []
          },
          {
            key: 'Aliases',
            value: Array.isArray(actor.aliases) ? actor.aliases : []
          },
          {
            key: 'Threat Actor Types',
            value: Array.isArray(actor.threatActorTypes) ? actor.threatActorTypes : []
          },
          {
            key: 'Description',
            value: actor.description
          }
        ]
      };
    }
  },
  report: {
    displayValue: 'Reports',
    icon: 'book',
    order: 0,
    getFields: (report) => {
      return {
        link: {
          display: 'View Report in FireEye Intel',
          url:
            report && report.x_fireeye_com_tracking_info && report.x_fireeye_com_tracking_info.document_id
              ? `${BASE_WEB_URL}/reports/${report.x_fireeye_com_tracking_info.document_id}`
              : null
        },
        fields: [
          {
            key: 'Name',
            value: report.name
          },
          {
            key: 'id',
            value: report.id
          },
          {
            key: 'Labels',
            value: report.labels
          },
          {
            key: 'Published',
            value: report.published
          },
          {
            key: 'Fireeye Metadata',
            nested: true,
            value: report.x_fireeye_com_metadata
          },
          {
            key: 'Description',
            value: report.description
          }
        ]
      };
    }
  },
  vulnerability: {
    displayValue: 'Vulnerabilities',
    icon: 'spider',
    order: 4,
    getFields: (vuln, entityObj) => {
      // Only return the vulnerability if Fireeye has a score for it
      if (Array.isArray(vuln.x_fireeye_com_vulnerability_score)) {
        return {
          link: {
            display: 'Search in FireEye Intel',
            url: `${BASE_WEB_URL}/search?search=${entityObj.value}`
          },
          fields: [
            {
              key: 'id',
              value: vuln.id
            },
            {
              key: 'Scores',
              nested: true,
              value: Array.isArray(vuln.x_fireeye_com_vulnerability_score)
                ? vuln.x_fireeye_com_vulnerability_score.map((vuln) => {
                    return {
                      Vector: _.get(vuln, 'vector'),
                      'Temporal Score': _.get(vuln, 'temporal_metrics.temporal_score'),
                      'Base Score': _.get(vuln, 'base_metrics.base_score')
                    };
                  })
                : []
            }
          ]
        };
      } else {
        return null;
      }
    }
  },
  file: {
    displayValue: 'Files',
    icon: 'file',
    order: 5,
    getFields: (file, entityObj) => {
      return {
        link: {
          display: 'Search in FireEye Intel',
          url: `${BASE_WEB_URL}/search?search=${entityObj.value}`
        },
        fields: [
          {
            key: 'Name',
            value: file.name
          },
          {
            key: 'id',
            value: file.id
          },
          {
            key: 'Size',
            value: file.size
          }
        ]
      };
    }
  },
  'email-addr': {
    displayValue: 'Email',
    icon: 'email',
    order: 6,
    getFields: (email, entityObj) => {
      return {
        link: {
          display: 'Search in FireEye Intel',
          url: `${BASE_WEB_URL}/search?search=${entityObj.value}`
        },
        fields: [
          {
            key: 'id',
            value: email.id
          },
          {
            key: 'Modified',
            value: email.modified
          }
        ]
      };
    }
  },
  'x-fireeye-com-remedy-action': {
    displayValue: 'Remedies',
    icon: 'prescription-bottle-alt',
    order: 7,
    getFields: (remedy) => {
      return {
        link: null,
        fields: [
          {
            key: 'Type',
            value: remedy.remedy_type
          },
          {
            key: 'id',
            value: remedy.id
          },
          {
            key: 'References',
            nested: true,
            value: Array.isArray(remedy.external_references) ? remedy.external_references : []
          },
          {
            key: 'Description',
            value: remedy.description
          }
        ]
      };
    }
  }
};
const MAX_RESULTS = 10;


module.exports = {
  legacyTypes,
  MAX_RESULTS
};
