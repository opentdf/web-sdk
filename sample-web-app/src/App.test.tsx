import * as React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect } from 'chai';
import App from './App.jsx';

describe('<App>', () => {
  it('renders', () => {
    render(<App />);
    const element = screen.getByText(/sum\(1,2\)\s*=\s*3/i);
    expect(document.body.contains(element)).to.be.ok;
  });

  it('loads files', async () => {
    const file = new File(['hello, world!'], 'hello.txt', { type: 'text/plain' });
    render(<App />);
    const input = screen.getByLabelText(/select file/i) as HTMLInputElement;
    userEvent.upload(input, file);
    const filenameEl = await screen.findByText(/hello.txt/i);
    expect(document.body.contains(filenameEl)).to.be.ok;
  });

  it('processes files', async () => {
    const file = new File(['hello, world!'], 'hello.txt', { type: 'text/plain' });
    render(<App />);
    const input = screen.getByLabelText(/select file/i) as HTMLInputElement;
    userEvent.upload(input, file);
    await screen.findByText(/hello.txt/i);
    const processButton = screen.getByText(/process/i) as HTMLInputElement;
    userEvent.click(processButton);
    const el = await screen.findByText(/start/i);
    expect(el.textContent).to.match(/start[:]\s*68/i);
  });
});
