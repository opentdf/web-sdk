function encode(str: string) {
  let hex = '';
  for (let i = 0; i < str.length; i++) {
    hex += `${str.charCodeAt(i).toString(16)}`;
  }
  return hex;
}

function decode(hex: string) {
  let str = '';
  for (let i = 0; i < hex.length; i += 2) {
    str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }
  return str;
}

export default { decode, encode };
