import * as React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect } from 'chai';
import App from './App.jsx';

describe('<App>', () => {
  it('renders', () => {
    render(<App />);
    const element = screen.getByText(/sum\(1\,2\)\s*=\s*3/i);
    expect(document.body.contains(element));
  });

  it('loads files', async () => {
    const file = new File(['hello, world!'], 'hello.txt', { type: 'text/plain' });
    render(<App />);
    const input = screen.getByLabelText(/select file/i) as HTMLInputElement;
    userEvent.upload(input, file);
    const filenameEl = await screen.findByText(/hello.txt/i);
    expect(document.body.contains(filenameEl));
  });

  it('processes files', async () => {
    console.log("process a");
    const file = new File(['hello, world!'], 'hello.txt', { type: 'text/plain' });
    render(<App />);
    const input = screen.getByLabelText(/select file/i) as HTMLInputElement;
    userEvent.upload(input, file);
    await screen.findByText(/hello.txt/i);
    const processButton = screen.getByText(/process/i) as HTMLInputElement;
    console.log("handles f", processButton);
    userEvent.click(processButton);
    console.log("handles g");
    // const el = await screen.findByText(/start[:] 68/i);
    // console.log(el);
  });
});
