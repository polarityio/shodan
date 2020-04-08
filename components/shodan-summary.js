'use strict';

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
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
  })
});
