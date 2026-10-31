import { WatchlistWorkbench } from "@/components/WatchlistWorkbench";
import { PageHeader } from "@/components/PageHeader";

export const metadata = { title: "Watchlist" };

export default function WatchlistPage() {
  return (
    <>
      <PageHeader
        index="05"
        kicker="Local memory"
        title={
          <>
            Remember
            <br />
            the repeat.
          </>
        }
        lead="Watch a phone number, domain, UPI ID, wallet or handle. Every later check that contains it raises a warning and increments a counter."
        meta={["Exact match", "0600 SQLite", "No sync"]}
      />
      <WatchlistWorkbench />
    </>
  );
}
