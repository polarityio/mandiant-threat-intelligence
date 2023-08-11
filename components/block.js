'use strict';

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  summary: Ember.computed.alias('block.data.summary'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  activeTab: '',

  displayTabNames: {
    indicatorV3: 'Indicator',
    collections: 'Collections',
    indicatorV4: 'Indicator',
    vulnerabilities: 'Vulnerabilities',
    searchResults: 'Search Results'
  },
  expandableTitleStates: Ember.computed.alias('block._state.expandableTitleStates'),

  init() {
    const details = this.get('details');
    this.set(
      'activeTab',
      details.indicatorV3
        ? 'indicatorV3'
        : details.collections && details.collections.length
        ? 'collections'
        : details.indicatorV4
        ? 'indicatorV4'
        : details.vulnerabilities && details.vulnerabilities.length
        ? 'vulnerabilities'
        : 'searchResults'
    );

    if (details.indicatorV3 && details.indicatorV4)
      this.set(
        'displayTabNames',
        Object.assign({}, this.get('displayTabNames'), {
          indicatorV3: 'Indicator V3',
          indicatorV4: 'Indicator V4'
        })
      );

    if (!this.get('block._state')) {
      this.set('block._state', {});
      this.set('block._state.expandableTitleStates', {});
    }

    this.set(
      'mispV4',
      Object.entries((details.indicatorV4 && details.indicatorV4.misp) || {}).filter(
        ([key, value]) => value
      )
    );

    this._super(...arguments);
  },
  actions: {
    changeTab: function (tabName) {
      this.set('activeTab', tabName);
    },
    toggleExpandableTitle: function (displayTab, index) {
      this.set(
        `block._state.expandableTitleStates`,
        Object.assign({}, this.get('block._state.expandableTitleStates'), {
          [displayTab + index]: !this.get('block._state.expandableTitleStates')[
            displayTab + index
          ]
        })
      );

      this.get('block').notifyPropertyChange('data');
    },
    retryLookup: function () {
      this.set('running', true);
      this.set('errorMessage', '');
      const payload = {
        action: 'RETRY_LOOKUP',
        entity: this.get('block.entity')
      };
      this.sendIntegrationMessage(payload)
        .then((result) => {
          if (result.data.summary) this.set('summary', result.summary);
          this.set('block.data', result.data);
        })
        .catch((err) => {
          this.set('details.errorMessage', JSON.stringify(err, null, 4));
        })
        .finally(() => {
          this.set('running', false);
        });
    }
  }
});
