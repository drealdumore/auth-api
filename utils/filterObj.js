/**
 * Filters an object to include only the specified allowed fields.
 * @param {Object} obj - The source object to filter.
 * @param {...string} allowedFields - The fields to keep in the returned object.
 * @returns {Object} - A new object with only the allowed fields.
 */
export const filterObj = (obj, ...allowedFields) => {
  return Object.keys(obj).reduce((acc, key) => {
    if (allowedFields.includes(key)) {
      acc[key] = obj[key];
    }
    return acc;
  }, {});
};
