function hexArrayTag(strings) {
  return (
    strings.raw[0]
      // Remove space beginning and end
      .trim()
      // Replace whitespace with single space
      .replace(/(\s{2,}|\n)/g, ' ')
      // Split on space
      .split(' ')
  );
}

function bufferToHex(buffer, uppercase = false) {
  return Array.from(buffer).map((i) => {
    // Convert to number (should already be a number)
    let num = Number(i);
    // Handle signed numbers
    if (num < 0) num = num >>> 0;
    // Convert to hex and pad with a zero if needed
    const hex = num.toString(16).padStart(2, '0');
    return uppercase ? hex.toUpperCase() : hex.toLowerCase();
  });
}

function hexToBase64(hexstring) {
  return btoa(
    hexstring
      .match(/\w{2}/g)
      .map(function (a) {
        return String.fromCharCode(parseInt(a, 16));
      })
      .join('')
  );
}
