import React from 'react';
import Auth from '../utils/auth';
import { useQuery } from '@apollo/client';
import { QUERY_THOUGHTS, QUERY_ME_BASIC } from '../utils/queries';
import ThoughtList from '../components/ThoughtList';
import FriendList from '../components/FriendList';
import ThoughtForm from '../components/ThoughtForm';

const Home = () => {
  // use useQuery hook to make query request
  const { loading, data } = useQuery(QUERY_THOUGHTS);
  // What we're saying is, if `data` exists, store it in the 
  // `thoughts constant` we just created. If data is `undefined`, 
  // then save an `empty array` to the thoughts component
  const thoughts = data?.thoughts || [];
  console.log(thoughts);
  // use object destructuring to extract `data` from the `useQuery` Hook's response and rename it
  // `userData` to be more desciptive
  const { data: userData } = useQuery(QUERY_ME_BASIC);
  const loggedIn = Auth.loggedIn();

  return (
    <main>
      <div className='flex-row justify-space-between'>
        {loggedIn && (
          <div className='col-12 mb-3'>
            <ThoughtForm />
          </div>
        )}
        <div className={`'col-12 mb-3'${loggedIn && 'col-lg-8'}`}>
          {/* PRINT THOUGHT LIST */
            loading ? (
              <div>Loading...</div>
            ) : (
              <ThoughtList thoughts={thoughts} title="Some Feed for Thought(s)..." />
            )
          }
          {loggedIn && userData ? (
            <div className='col-12 col-lg-3 mb-3'>
              <FriendList
                username={userData.me.username}
                friendCount={userData.me.friendCount}
                friends={userData.me.friends}
              />
            </div>
          ) : null}
        </div>
      </div>
    </main>
  );
};

export default Home;
