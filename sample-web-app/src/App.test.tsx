import * as React from 'react';
import { render } from '@testing-library/react';
import { expect } from 'chai';
import App from './App';

describe('<App>', () => {
  it('renders learn react link', () => {
    const { getByText } = render(<App />);
    const linkElement = getByText(/sum\(1\,2\)\s*=\s*3/i);
    expect(document.body.contains(linkElement));
  });
});
