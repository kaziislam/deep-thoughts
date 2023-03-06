import React from 'react';
import { useQuery } from '@apollo/client';
import { QUERY_THOUGHTS } from '../utils/queries';
import ThoughtList from '../components/ThoughtList';

const Home = () => {
  // use useQuery hook to make query request
  const {loading, data} = useQuery(QUERY_THOUGHTS);
  // What we're saying is, if `data` exists, store it in the 
  // `thoughts constant` we just created. If data is `undefined`, 
  // then save an `empty array` to the thoughts component
  const thoughts = data?.thoughts || [];
  console.log(thoughts);

  return (
    <main>
      <div className='flex-row justify-space-between'>
        <div className='col-12 mb-3'>
          {/* PRINT THOUGHT LIST */
            loading ? (
              <div>Loading...</div>
            ) : (
              <ThoughtList thoughts={thoughts} title="Some Feed for Thought(s)..." />
            )
          }
        </div>
      </div>
    </main>
  );
};

export default Home;
