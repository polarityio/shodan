'use strict';

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  entity: Ember.computed.alias('block.entity'),
  summaryTags: Ember.computed('details.tags', function() {
    let summaryTags = [];

    let location = '';
    const country = this.get('details.country_name');
    const city = this.get('details.city');

    if (city && country) {
      location = `${city}, ${country}`;
    } else if (city) {
      location = city;
    } else if (country) {
      location = country;
    }

    if (location) {
      summaryTags.push(location);
    }

    if (this.get('details.isp')) {
      summaryTags.push(`ISP: ${this.get('details.isp')}`);
    }

    if (this.get('details.org')) {
      summaryTags.push(`Org: ${this.get('details.org')}`);
    }

    let tags = this.get('details.tags');
    if (Array.isArray(tags)) {
      summaryTags = summaryTags.concat(tags);
    }

    if (summaryTags.length === 0) {
      summaryTags.push('No Tags');
    }
    return summaryTags;
  }),
  actions: {
    tryAgain: function() {
      const outerThis = this;

      this.set('message', '');
      this.set('errorMessage', '');
      this.set('isRunning', true);

      this.sendIntegrationMessage({ data: { entity: this.entity } })
        .then((newDetails) => {
          outerThis.set('message', 'Success!');
          outerThis.set('details', newDetails);
        })
        .catch((err) => {
          outerThis.set(
            'errorMessage',
            `Failed on Retry: ${err.message || err.title || err.description || 'Unknown Reason'}`
          );
        })
        .finally(() => {
          this.set('isRunning', false);
          outerThis.get('block').notifyPropertyChange('data');
        });
    }
  }
});
