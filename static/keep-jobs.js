(() => {
  'use strict';
  const format = new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium', timeStyle: 'short',
  });
  document.querySelectorAll('.jobs-ui time[datetime]').forEach((element) => {
    const date = new Date(element.dateTime);
    if (Number.isNaN(date.getTime())) return;
    element.textContent = format.format(date);
    element.title = date.toLocaleString(undefined, { timeZoneName: 'short' });
  });
})();
