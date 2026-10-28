import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import App from '../App'

function makeIncident(id: number) {
  return {
    id,
    source: 'kubernetes',
    logs: `Test incident ${id}`,
    analysis_json: '{}',
    verification_status: 'passed',
    verification_notes: null,
    fix_description: null,
    created_at: '2026-10-28T10:00:00',
    verified_at: null,
  }
}

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as Response
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('incident history pagination', () => {
  it('loads the next page using the correct offset and avoids duplicate incidents', async () => {
    const firstPage = Array.from({ length: 50 }, (_, index) =>
      makeIncident(index + 1),
    )
    const nextPage = [makeIncident(50), makeIncident(51)]
    const requestedUrls: string[] = []

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      requestedUrls.push(url)

      if (url === '/health') {
        return jsonResponse({ status: 'ok' })
      }

      if (url === '/api/v1/auth/me') {
        return jsonResponse({ authenticated: true, username: 'test-user' })
      }

      if (url === '/api/v1/incidents?limit=50&offset=0') {
        return jsonResponse({
          items: firstPage,
          limit: 50,
          offset: 0,
        })
      }

      if (url === '/api/v1/incidents?limit=50&offset=50') {
        return jsonResponse({
          items: nextPage,
          limit: 50,
          offset: 50,
        })
      }

      return jsonResponse({ detail: `Unexpected request: ${url}` }, 404)
    })

    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    const loadMoreButton = await screen.findByRole('button', {
      name: 'Load more incidents',
    })

    expect(screen.getByRole('button', { name: 'Open incident 1' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Open incident 50' })).toBeTruthy()

    fireEvent.click(loadMoreButton)

    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: 'Open incident 51' }),
      ).toBeTruthy()
    })

    expect(
      screen.getAllByRole('button', { name: 'Open incident 50' }),
    ).toHaveLength(1)

    expect(requestedUrls).toContain('/api/v1/incidents?limit=50&offset=50')
  })
})
