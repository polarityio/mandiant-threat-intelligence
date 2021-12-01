'use strict';

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  summary: Ember.computed.alias("block.data.summary"),
  timezone: Ember.computed('Intl', function() {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  actions: {
    retryLookup: function () {
      this.set("running", true);
      this.set("errorMessage", "");
      const payload = {
        action: "RETRY_LOOKUP",
        entity: this.get("block.entity"),
      };
      this.sendIntegrationMessage(payload)
        .then((result) => {
          if (result.data.summary) this.set("summary", result.summary);
          this.set("block.data", result.data);
        })
        .catch((err) => {
          this.set("details.errorMessage", JSON.stringify(err, null, 4));
        })
        .finally(() => {
          this.set("running", false);
        });
    },
  },
});
